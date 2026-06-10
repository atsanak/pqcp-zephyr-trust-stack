/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * End-to-end firmware deployment evidence pipeline.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/deployment_pipeline.h>

static void set_pipeline_error(struct pqcp_deployment_pipeline_result *result,
			       uint32_t error)
{
	if (result != NULL) {
		result->error_mask |= error;
	}
}

static bool profile_valid(enum pqcp_deployment_appraisal_profile profile)
{
	return profile >= PQCP_DEPLOYMENT_APPRAISAL_PROFILE_LAB &&
	       profile <= PQCP_DEPLOYMENT_APPRAISAL_PROFILE_HARDWARE_REVIEW;
}

static bool has_campaign(const struct pqcp_deployment_pipeline_config *config)
{
	return config != NULL &&
	       config->campaign != NULL &&
	       config->campaign->observations != NULL &&
	       config->campaign->observation_count != 0U;
}

static int validate_config(
	const struct pqcp_deployment_pipeline_config *config,
	const char *trace_buffer,
	size_t trace_buffer_size)
{
	if (config == NULL ||
	    pqcp_deployment_scenario_validate(config->scenario) != 0 ||
	    config->candidates == NULL || config->candidate_count == 0U ||
	    config->candidate_count > PQCP_DEPLOYMENT_MAX_CANDIDATES ||
	    !profile_valid(config->appraisal_profile) ||
	    trace_buffer == NULL || trace_buffer_size < 2U) {
		return -EINVAL;
	}

	if (has_campaign(config)) {
		if (config->campaign->campaign_id == NULL ||
		    config->campaign->observation_count >
			    PQCP_DEPLOYMENT_CAMPAIGN_MAX_OBSERVATIONS ||
		    config->candidate_count + 1U >
			    PQCP_DEPLOYMENT_MAX_CANDIDATES ||
		    pqcp_deployment_candidate_validate(
			    &config->campaign->candidate_template) != 0) {
			return -EINVAL;
		}
	}

	return 0;
}

static void clear_result(struct pqcp_deployment_pipeline_result *result)
{
	memset(result, 0, sizeof(*result));
	result->schema_version = PQCP_DEPLOYMENT_PIPELINE_SCHEMA_VERSION;
	result->top_candidate_id = "none";
	result->advisor_report.top_result_index = UINT32_MAX;
	result->robustness_report.top_candidate_index = UINT32_MAX;
}

static int copy_candidates(
	const struct pqcp_deployment_pipeline_config *config,
	struct pqcp_deployment_pipeline_workspace *workspace,
	struct pqcp_deployment_pipeline_result *result)
{
	for (size_t i = 0U; i < config->candidate_count; ++i) {
		if (pqcp_deployment_candidate_validate(&config->candidates[i]) != 0) {
			set_pipeline_error(result,
					   PQCP_DEPLOYMENT_PIPELINE_ERROR_INVALID_INPUT);
			return -EINVAL;
		}
		workspace->candidates[i] = config->candidates[i];
	}

	result->candidate_count = (uint32_t)config->candidate_count;
	return 0;
}

static int run_campaign(
	const struct pqcp_deployment_pipeline_config *config,
	struct pqcp_deployment_pipeline_workspace *workspace,
	struct pqcp_deployment_pipeline_result *result)
{
	struct pqcp_deployment_campaign_state state;
	struct pqcp_deployment_campaign_config campaign_config;
	int ret;

	if (!has_campaign(config)) {
		return 0;
	}

	if (result->candidate_count >= PQCP_DEPLOYMENT_MAX_CANDIDATES) {
		set_pipeline_error(result,
				   PQCP_DEPLOYMENT_PIPELINE_ERROR_CANDIDATE_SPACE);
		return -ENOSPC;
	}

	campaign_config = (struct pqcp_deployment_campaign_config) {
		.campaign_id = config->campaign->campaign_id,
		.candidate_template = config->campaign->candidate_template,
		.projection = config->campaign->projection,
		.min_samples = config->campaign->min_samples,
		.cv_warn_bps = config->campaign->cv_warn_bps,
		.static_drift_warn_permille =
			config->campaign->static_drift_warn_permille,
	};

	ret = pqcp_deployment_campaign_init(
		&state, &campaign_config, workspace->campaign_observations,
		config->campaign->observation_count);
	if (ret != 0) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_CAMPAIGN);
		return ret;
	}

	for (size_t i = 0U; i < config->campaign->observation_count; ++i) {
		ret = pqcp_deployment_campaign_add(
			&state, &config->campaign->observations[i]);
		if (ret != 0) {
			set_pipeline_error(result,
					   PQCP_DEPLOYMENT_PIPELINE_ERROR_CAMPAIGN);
			return ret;
		}
	}

	ret = pqcp_deployment_campaign_summarize(&state,
						 &result->campaign_summary);
	if (ret != 0) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_CAMPAIGN);
		return ret;
	}
	if (!result->campaign_summary.projected_candidate_valid) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_CAMPAIGN);
		return 0;
	}

	workspace->candidates[result->candidate_count] =
		result->campaign_summary.projected_candidate;
	result->candidate_count++;

	return 0;
}

static int run_analysis(
	const struct pqcp_deployment_pipeline_config *config,
	struct pqcp_deployment_pipeline_workspace *workspace,
	struct pqcp_deployment_pipeline_result *result)
{
	size_t gap_count = 0U;
	int ret;

	ret = pqcp_deployment_robustness_analyze(
		config->scenario, workspace->candidates, result->candidate_count,
		workspace->results, workspace->robustness,
		&result->advisor_report, &result->robustness_report);
	if (ret != 0) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_ANALYSIS);
		return ret;
	}

	ret = pqcp_deployment_plan_gaps(
		config->scenario, workspace->candidates, workspace->results,
		result->candidate_count, workspace->gaps, ARRAY_SIZE(workspace->gaps),
		&gap_count);
	result->gap_count = (uint32_t)gap_count;
	if (ret != 0 && ret != -ENOSPC) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_ANALYSIS);
		return ret;
	}
	if (ret == -ENOSPC) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_ANALYSIS);
	}

	result->recommendation_ready =
		result->advisor_report.recommendation_ready;
	if (result->advisor_report.top_result_index != UINT32_MAX &&
	    result->advisor_report.top_result_index < result->candidate_count) {
		const struct pqcp_deployment_candidate_result *top =
			&workspace->results[result->advisor_report.top_result_index];

		result->top_candidate_id = top->candidate_id;
		result->top_candidate_score = top->score;
	}

	return 0;
}

static void note_trace_ret(struct pqcp_deployment_pipeline_result *result,
			   int ret)
{
	if (ret != 0) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_TRACE);
	}
}

static int append_trace(
	const struct pqcp_deployment_pipeline_config *config,
	struct pqcp_deployment_pipeline_workspace *workspace,
	char *trace_buffer,
	size_t trace_buffer_size,
	struct pqcp_deployment_pipeline_result *result)
{
	struct pqcp_deployment_trace_builder builder;
	int ret;
	int overflow_ret = 0;

	ret = pqcp_deployment_trace_builder_init(
		&builder, trace_buffer, trace_buffer_size);
	if (ret != 0) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_TRACE);
		return ret;
	}

	if (has_campaign(config)) {
		ret = pqcp_deployment_trace_builder_append_campaign(
			&builder, &result->campaign_summary);
		note_trace_ret(result, ret);
		if (ret == -ENOSPC) {
			overflow_ret = ret;
		}
	}

	ret = pqcp_deployment_trace_builder_append_scenario(
		&builder, config->scenario);
	note_trace_ret(result, ret);
	if (ret == -ENOSPC) {
		overflow_ret = ret;
	}

	for (size_t i = 0U; i < result->candidate_count; ++i) {
		ret = pqcp_deployment_trace_builder_append_candidate(
			&builder, config->scenario, &workspace->candidates[i],
			&workspace->results[i]);
		note_trace_ret(result, ret);
		if (ret == -ENOSPC) {
			overflow_ret = ret;
		}
		ret = pqcp_deployment_trace_builder_append_robust_candidate(
			&builder, &workspace->robustness[i]);
		note_trace_ret(result, ret);
		if (ret == -ENOSPC) {
			overflow_ret = ret;
		}
	}

	ret = pqcp_deployment_trace_builder_append_decision(
		&builder, &result->advisor_report, workspace->results);
	note_trace_ret(result, ret);
	if (ret == -ENOSPC) {
		overflow_ret = ret;
	}
	ret = pqcp_deployment_trace_builder_append_robustness(
		&builder, &result->robustness_report, workspace->robustness);
	note_trace_ret(result, ret);
	if (ret == -ENOSPC) {
		overflow_ret = ret;
	}

	for (size_t i = 0U; i < result->gap_count; ++i) {
		ret = pqcp_deployment_trace_builder_append_gap(
			&builder, &workspace->gaps[i]);
		note_trace_ret(result, ret);
		if (ret == -ENOSPC) {
			overflow_ret = ret;
		}
	}

	ret = pqcp_deployment_trace_builder_finish(
		&builder, &result->trace_digest);
	if (ret != 0) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_TRACE);
	}
	result->replay_passed = result->trace_digest.passed;

	return overflow_ret != 0 ? overflow_ret : 0;
}

static int run_appraisal(
	const struct pqcp_deployment_pipeline_config *config,
	struct pqcp_deployment_pipeline_result *result)
{
	struct pqcp_deployment_appraisal_policy policy;
	int ret;

	ret = pqcp_deployment_appraisal_default_policy(
		config->appraisal_profile, &policy);
	if (ret != 0) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_APPRAISAL);
		return ret;
	}
	ret = pqcp_deployment_appraisal_evaluate(
		&result->trace_digest.replay_result, &policy, &result->appraisal);
	if (ret != 0) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_APPRAISAL);
		return ret;
	}
	result->appraisal_passed = result->appraisal.passed;
	if (!result->appraisal.passed) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_APPRAISAL);
	}

	return 0;
}

static int run_claims(
	struct pqcp_deployment_pipeline_workspace *workspace,
	struct pqcp_deployment_pipeline_result *result)
{
	struct pqcp_deployment_claim_inputs inputs = {
		.advisor_report = &result->advisor_report,
		.robustness_report = &result->robustness_report,
		.transcript_result = &result->trace_digest.replay_result,
		.appraisal = &result->appraisal,
	};
	int ret = pqcp_deployment_claims_evaluate(
		&inputs, workspace->claims, ARRAY_SIZE(workspace->claims),
		&result->claim_matrix);

	if (ret != 0) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_CLAIMS);
		return ret;
	}
	result->claims_passed = result->claim_matrix.passed;
	if (!result->claim_matrix.passed) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_CLAIMS);
	}

	return 0;
}

static void finalize_result(struct pqcp_deployment_pipeline_result *result)
{
	result->passed =
		result->error_mask == 0U &&
		result->recommendation_ready &&
		result->replay_passed &&
		result->appraisal_passed &&
		result->claims_passed;
}

static void emit_claim_rows(
	const struct pqcp_deployment_pipeline_workspace *workspace,
	const struct pqcp_deployment_pipeline_result *result)
{
	for (size_t i = 0U; i < result->claim_matrix.claim_count &&
	     i < ARRAY_SIZE(workspace->claims); ++i) {
		(void)pqcp_deployment_claim_row_emit(&workspace->claims[i]);
	}
}

int pqcp_deployment_pipeline_run(
	const struct pqcp_deployment_pipeline_config *config,
	struct pqcp_deployment_pipeline_workspace *workspace,
	char *trace_buffer,
	size_t trace_buffer_size,
	struct pqcp_deployment_pipeline_result *result)
{
	int ret;

	if (workspace == NULL || result == NULL) {
		return -EINVAL;
	}
	memset(workspace, 0, sizeof(*workspace));
	clear_result(result);

	ret = validate_config(config, trace_buffer, trace_buffer_size);
	if (ret != 0) {
		set_pipeline_error(result, PQCP_DEPLOYMENT_PIPELINE_ERROR_INVALID_INPUT);
		finalize_result(result);
		return ret;
	}

	ret = copy_candidates(config, workspace, result);
	if (ret != 0) {
		finalize_result(result);
		return ret;
	}
	ret = run_campaign(config, workspace, result);
	if (ret != 0) {
		finalize_result(result);
		return ret;
	}
	ret = run_analysis(config, workspace, result);
	if (ret != 0) {
		finalize_result(result);
		return ret;
	}
	ret = append_trace(config, workspace, trace_buffer, trace_buffer_size,
			   result);
	if (ret == -ENOSPC) {
		finalize_result(result);
		return ret;
	}
	(void)run_appraisal(config, result);
	(void)run_claims(workspace, result);
	finalize_result(result);

	if (config->emit_markers) {
		printk("%s", trace_buffer);
		(void)pqcp_deployment_trace_digest_emit(&result->trace_digest);
		(void)pqcp_deployment_appraisal_emit(&result->appraisal);
		emit_claim_rows(workspace, result);
		(void)pqcp_deployment_claim_matrix_emit(&result->claim_matrix);
		(void)pqcp_deployment_pipeline_result_emit(result);
	}

	return 0;
}

int pqcp_deployment_pipeline_result_emit(
	const struct pqcp_deployment_pipeline_result *result)
{
	if (result == NULL ||
	    result->schema_version != PQCP_DEPLOYMENT_PIPELINE_SCHEMA_VERSION ||
	    (result->error_mask &
	     ~PQCP_DEPLOYMENT_PIPELINE_ERROR_KNOWN_MASK) != 0U ||
	    result->top_candidate_id == NULL ||
	    result->top_candidate_score > 100U ||
	    result->claim_matrix.average_score > 100U ||
	    result->passed !=
		    (result->error_mask == 0U &&
		     result->recommendation_ready &&
		     result->replay_passed &&
		     result->appraisal_passed &&
		     result->claims_passed)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_PIPELINE schema=%u status=%s errors=0x%08x candidates=%u gaps=%u top=%s top_score=%u replay=%s appraisal=%s claims=%s readiness=%u claim_score=%u digest=%s\n",
	       result->schema_version,
	       result->passed ? "PASS" : "FAIL",
	       result->error_mask,
	       result->candidate_count,
	       result->gap_count,
	       result->top_candidate_id,
	       result->top_candidate_score,
	       result->replay_passed ? "PASS" : "FAIL",
	       result->appraisal_passed ? "PASS" : "FAIL",
	       result->claims_passed ? "PASS" : "FAIL",
	       result->appraisal.readiness_score,
	       result->claim_matrix.average_score,
	       result->trace_digest.digest_hex[0] != '\0' ?
		       result->trace_digest.digest_hex : "none");

	return result->passed ? 0 : -EBADMSG;
}
