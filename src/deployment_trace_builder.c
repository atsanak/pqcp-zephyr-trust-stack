/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free deployment evidence trace builder.
 */

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/deployment_trace_builder.h>

static bool builder_valid(const struct pqcp_deployment_trace_builder *builder)
{
	return builder != NULL &&
	       builder->schema_version ==
		       PQCP_DEPLOYMENT_TRACE_BUILDER_SCHEMA_VERSION &&
	       builder->buffer != NULL &&
	       builder->capacity != 0U &&
	       builder->length < builder->capacity;
}

static void set_error(
	struct pqcp_deployment_trace_builder *builder,
	uint32_t error)
{
	if (builder == NULL) {
		return;
	}
	if (builder->first_error == 0U) {
		builder->first_error = error;
	}
	builder->error_mask |= error;
}

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0xcbf29ce484222325ULL;
	digest[1] = 0x84222325cbf29ce4ULL;
	digest[2] = 0x9e3779b97f4a7c15ULL;
	digest[3] = 0x6a09e667f3bcc909ULL;
}

static uint64_t rotate_left64(uint64_t value, uint32_t bits)
{
	return (value << bits) | (value >> (64U - bits));
}

static void digest_update_byte(uint64_t digest[4], uint8_t value)
{
	digest[0] ^= value;
	digest[0] *= 0x100000001b3ULL;
	digest[1] += digest[0] ^ ((uint64_t)value << 17U);
	digest[1] = rotate_left64(digest[1], 13U) * 0x9e3779b185ebca87ULL;
	digest[2] ^= digest[1] + value + 0x517cc1b727220a95ULL;
	digest[2] = rotate_left64(digest[2], 29U);
	digest[3] += digest[2] ^ (digest[0] >> 7U);
	digest[3] = rotate_left64(digest[3], 41U);
}

static void digest_update(uint64_t digest[4], const char *line)
{
	for (const char *p = line; *p != '\0'; ++p) {
		digest_update_byte(digest, (uint8_t)*p);
	}
	digest_update_byte(digest, (uint8_t)'\n');
}

static void digest_to_hex(const uint64_t digest[4], char out[
			  PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(out, PQCP_DEPLOYMENT_TRACE_DIGEST_HEX_CHARS + 1U,
		       "%016llx%016llx%016llx%016llx",
		       (unsigned long long)digest[0],
		       (unsigned long long)digest[1],
		       (unsigned long long)digest[2],
		       (unsigned long long)digest[3]);
}

static int append_formatted(
	struct pqcp_deployment_trace_builder *builder,
	const char *fmt,
	...)
{
	char line[PQCP_DEPLOYMENT_TRACE_LINE_MAX];
	va_list args;
	int written;

	if (!builder_valid(builder) || fmt == NULL || builder->finished) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_NOT_INITIALIZED);
		return -EINVAL;
	}

	va_start(args, fmt);
	written = vsnprintk(line, sizeof(line), fmt, args);
	va_end(args);

	if (written < 0 || written >= (int)sizeof(line)) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_LINE_TOO_LONG);
		return -ENOSPC;
	}

	return pqcp_deployment_trace_builder_append_line(builder, line);
}

static int append_metric(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_campaign_summary *summary,
	const struct pqcp_deployment_metric_stats *stats)
{
	if (summary == NULL || stats == NULL || stats->name == NULL) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT);
		return -EINVAL;
	}

	return append_formatted(
		builder,
		"PQCP_DEPLOYMENT_CAMPAIGN_METRIC campaign=%s metric=%s count=%u missing=%u min=%llu median=%llu p90=%llu p99=%llu max=%llu mean=%llu mad=%llu cv_bps=%u outliers=%u stable=%u",
		summary->campaign_id,
		stats->name,
		stats->count,
		stats->missing_count,
		(unsigned long long)stats->min,
		(unsigned long long)stats->median,
		(unsigned long long)stats->p90,
		(unsigned long long)stats->p99,
		(unsigned long long)stats->max,
		(unsigned long long)stats->mean,
		(unsigned long long)stats->mad,
		stats->cv_bps,
		stats->outlier_count,
		stats->stable ? 1U : 0U);
}

int pqcp_deployment_trace_builder_init(
	struct pqcp_deployment_trace_builder *builder,
	char *buffer,
	size_t capacity)
{
	if (builder == NULL || buffer == NULL || capacity < 2U) {
		return -EINVAL;
	}

	memset(builder, 0, sizeof(*builder));
	memset(buffer, 0, capacity);
	builder->schema_version = PQCP_DEPLOYMENT_TRACE_BUILDER_SCHEMA_VERSION;
	builder->buffer = buffer;
	builder->capacity = capacity;
	digest_init(builder->digest_words);

	return pqcp_deployment_transcript_init(&builder->replay_state);
}

int pqcp_deployment_trace_builder_append_line(
	struct pqcp_deployment_trace_builder *builder,
	const char *line)
{
	size_t len;
	int ret;

	if (!builder_valid(builder) || line == NULL || line[0] == '\0' ||
	    builder->finished) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_NOT_INITIALIZED);
		return -EINVAL;
	}

	len = strlen(line);
	if (len + 2U > builder->capacity - builder->length) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_OVERFLOW);
		return -ENOSPC;
	}

	memcpy(&builder->buffer[builder->length], line, len);
	builder->length += len;
	builder->buffer[builder->length++] = '\n';
	builder->buffer[builder->length] = '\0';
	builder->line_count++;
	digest_update(builder->digest_words, line);

	ret = pqcp_deployment_transcript_ingest_line(
		&builder->replay_state, line);
	if (ret != 0) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_REPLAY_APPEND);
		return ret;
	}

	return 0;
}

int pqcp_deployment_trace_builder_append_campaign(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_campaign_summary *summary)
{
	const struct pqcp_deployment_metric_stats *stats[7];
	int ret;

	if (!builder_valid(builder) || summary == NULL ||
	    summary->schema_version != PQCP_DEPLOYMENT_CAMPAIGN_SCHEMA_VERSION ||
	    summary->campaign_id == NULL) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT);
		return -EINVAL;
	}

	stats[0] = &summary->latency;
	stats[1] = &summary->cycles;
	stats[2] = &summary->ram;
	stats[3] = &summary->stack;
	stats[4] = &summary->heap;
	stats[5] = &summary->flash;
	stats[6] = &summary->energy;

	ret = append_formatted(
		builder,
		"PQCP_DEPLOYMENT_CAMPAIGN_SUMMARY schema=%u id=%s projection=%s observations=%u successful=%u failed=%u quality=0x%08x projected=%u candidate=%s evidence=0x%08x",
		summary->schema_version,
		summary->campaign_id,
		pqcp_deployment_campaign_projection_str(summary->projection),
		summary->observation_count,
		summary->successful_count,
		summary->failed_count,
		summary->quality_mask,
		summary->projected_candidate_valid ? 1U : 0U,
		summary->projected_candidate_valid ?
			summary->projected_candidate.candidate_id : "none",
		summary->projected_candidate_valid ?
			summary->projected_candidate.evidence_mask : 0U);
	if (ret != 0) {
		return ret;
	}

	for (size_t i = 0U; i < ARRAY_SIZE(stats); ++i) {
		ret = append_metric(builder, summary, stats[i]);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

int pqcp_deployment_trace_builder_append_scenario(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_scenario *scenario)
{
	if (pqcp_deployment_scenario_validate(scenario) != 0) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT);
		return -EINVAL;
	}

	return append_formatted(
		builder,
		"PQCP_DEPLOYMENT_SCENARIO schema=%u id=%s operation=%s target=%s security=%u preference=%s evidence_level=%s latency_budget_us=%llu ram_budget=%llu stack_budget=%llu heap_budget=%llu flash_budget=%llu energy_budget_uj=%llu native_required=%u hardware_required=%u",
		PQCP_DEPLOYMENT_ADVISOR_SCHEMA_VERSION,
		scenario->scenario_id,
		pqcp_deployment_operation_str(scenario->operation),
		pqcp_deployment_target_class_str(scenario->target_class),
		scenario->minimum_security_level,
		pqcp_deployment_preference_str(scenario->preference),
		pqcp_deployment_evidence_level_str(
			scenario->required_evidence_level),
		(unsigned long long)scenario->latency_budget_us,
		(unsigned long long)scenario->ram_budget_bytes,
		(unsigned long long)scenario->stack_budget_bytes,
		(unsigned long long)scenario->heap_budget_bytes,
		(unsigned long long)scenario->flash_budget_bytes,
		(unsigned long long)scenario->energy_budget_uj,
		scenario->require_native_provider ? 1U : 0U,
		scenario->require_hardware_evidence ? 1U : 0U);
}

int pqcp_deployment_trace_builder_append_candidate(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_scenario *scenario,
	const struct pqcp_deployment_candidate *candidate,
	const struct pqcp_deployment_candidate_result *result)
{
	if (pqcp_deployment_scenario_validate(scenario) != 0 ||
	    pqcp_deployment_candidate_validate(candidate) != 0 ||
	    result == NULL || result->candidate_id == NULL ||
	    strcmp(result->candidate_id, candidate->candidate_id) != 0 ||
	    result->score > 100U || result->confidence > 100U) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT);
		return -EINVAL;
	}

	return append_formatted(
		builder,
		"PQCP_DEPLOYMENT_CANDIDATE scenario=%s rank=%u id=%s kind=%s target=%s status=%s score=%u confidence=%u blockers=0x%08x gaps=0x%08x security=%u mlkem=%u mldsa=%u latency_us=%llu ram=%llu stack=%llu heap=%llu flash=%llu energy_uj=%llu evidence=0x%08x independent=%u",
		scenario->scenario_id,
		result->rank,
		candidate->candidate_id,
		pqcp_deployment_candidate_kind_str(candidate->kind),
		pqcp_deployment_target_class_str(candidate->target_class),
		pqcp_deployment_recommendation_status_str(result->status),
		result->score,
		result->confidence,
		result->blocker_mask,
		result->gap_mask,
		candidate->security_level,
		candidate->mlkem_level,
		candidate->mldsa_level,
		(unsigned long long)candidate->latency_us,
		(unsigned long long)candidate->ram_bytes,
		(unsigned long long)candidate->stack_bytes,
		(unsigned long long)candidate->heap_bytes,
		(unsigned long long)candidate->flash_bytes,
		(unsigned long long)candidate->energy_uj,
		candidate->evidence_mask,
		candidate->independent_evidence ? 1U : 0U);
}

int pqcp_deployment_trace_builder_append_robust_candidate(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_candidate_robustness *robustness)
{
	if (robustness == NULL || robustness->candidate_id == NULL ||
	    robustness->robustness_score > 100U) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT);
		return -EINVAL;
	}

	return append_formatted(
		builder,
		"PQCP_DEPLOYMENT_ROBUSTNESS_CANDIDATE schema=%u index=%u id=%s status=%s score=%u configured=0x%08x measured=0x%08x missing=0x%08x binding=%s min_headroom_permille=%d avg_headroom_permille=%d preference_wins=0x%08x stress_pass=0x%08x max_reduction_percent=%u dominates=%u dominated_by=%u pareto=%u complete=%u",
		PQCP_DEPLOYMENT_ROBUSTNESS_SCHEMA_VERSION,
		robustness->candidate_index,
		robustness->candidate_id,
		pqcp_deployment_robustness_status_str(robustness->status),
		robustness->robustness_score,
		robustness->configured_metric_mask,
		robustness->measured_metric_mask,
		robustness->missing_metric_mask,
		pqcp_deployment_metric_str(robustness->binding_metric),
		robustness->minimum_headroom_permille,
		robustness->average_headroom_permille,
		robustness->preference_win_mask,
		robustness->stress_pass_mask,
		robustness->maximum_uniform_budget_reduction_percent,
		robustness->dominates_count,
		robustness->dominated_by_count,
		robustness->pareto_frontier ? 1U : 0U,
		robustness->measurements_complete ? 1U : 0U);
}

int pqcp_deployment_trace_builder_append_decision(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_report *report,
	const struct pqcp_deployment_candidate_result *results)
{
	const char *status;
	const char *top_id = "none";
	uint32_t top_score = 0U;
	uint32_t top_confidence = 0U;

	if (report == NULL || results == NULL ||
	    report->schema_version != PQCP_DEPLOYMENT_ADVISOR_SCHEMA_VERSION ||
	    report->candidate_count == 0U ||
	    report->candidate_count > PQCP_DEPLOYMENT_MAX_CANDIDATES) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT);
		return -EINVAL;
	}
	if (report->top_result_index != UINT32_MAX) {
		if (report->top_result_index >= report->candidate_count) {
			set_error(builder,
				  PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT);
			return -EINVAL;
		}
		top_id = results[report->top_result_index].candidate_id;
		top_score = results[report->top_result_index].score;
		top_confidence = results[report->top_result_index].confidence;
	}

	status = report->recommendation_ready ? "PASS" :
		(report->conditional_count > 0U ? "WARN" : "FAIL");
	return append_formatted(
		builder,
		"PQCP_DEPLOYMENT_DECISION schema=%u id=%s status=%s candidates=%u feasible=%u accepted=%u conditional=%u rejected=%u top=%s top_score=%u top_confidence=%u",
		report->schema_version,
		report->scenario_id,
		status,
		report->candidate_count,
		report->feasible_count,
		report->accepted_count,
		report->conditional_count,
		report->rejected_count,
		top_id,
		top_score,
		top_confidence);
}

int pqcp_deployment_trace_builder_append_robustness(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_robustness_report *report,
	const struct pqcp_deployment_candidate_robustness *results)
{
	const char *top_id = "none";
	const char *status = "NO_RECOMMENDATION";

	if (report == NULL || results == NULL ||
	    report->schema_version != PQCP_DEPLOYMENT_ROBUSTNESS_SCHEMA_VERSION ||
	    report->candidate_count == 0U ||
	    report->candidate_count > PQCP_DEPLOYMENT_MAX_CANDIDATES) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT);
		return -EINVAL;
	}
	if (report->top_candidate_index != UINT32_MAX) {
		if (report->top_candidate_index >= report->candidate_count) {
			set_error(builder,
				  PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT);
			return -EINVAL;
		}
		top_id = results[report->top_candidate_index].candidate_id;
		status = report->recommendation_robust ? "ROBUST" :
			(report->recommendation_stable ? "STABLE" : "SENSITIVE");
	}

	return append_formatted(
		builder,
		"PQCP_DEPLOYMENT_ROBUSTNESS schema=%u id=%s status=%s candidates=%u feasible=%u frontier=%u top=%s top_score=%u top_preference_wins=%u stable=%u robust=%u",
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
}

int pqcp_deployment_trace_builder_append_gap(
	struct pqcp_deployment_trace_builder *builder,
	const struct pqcp_deployment_gap_plan_entry *entry)
{
	if (entry == NULL || entry->candidate_id == NULL ||
	    entry->expected_artifact == NULL || entry->claim_token == NULL ||
	    entry->priority == 0U) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_INVALID_OBJECT);
		return -EINVAL;
	}

	return append_formatted(
		builder,
		"PQCP_DEPLOYMENT_GAP priority=%u candidate=%s gap=%s maturity=%s acceptance_max=%llu expected=%s claim=%s",
		entry->priority,
		entry->candidate_id,
		pqcp_deployment_gap_str(entry->gap),
		pqcp_deployment_evidence_level_str(entry->maturity),
		(unsigned long long)entry->acceptance_max,
		entry->expected_artifact,
		entry->claim_token);
}

int pqcp_deployment_trace_builder_finish(
	struct pqcp_deployment_trace_builder *builder,
	struct pqcp_deployment_trace_digest *digest)
{
	int ret;

	if (!builder_valid(builder) || digest == NULL || builder->finished) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_NOT_INITIALIZED);
		return -EINVAL;
	}

	memset(digest, 0, sizeof(*digest));
	builder->finished = true;
	ret = pqcp_deployment_transcript_finish(
		&builder->replay_state, &digest->replay_result);
	if (ret != 0) {
		set_error(builder, PQCP_DEPLOYMENT_TRACE_ERROR_REPLAY_FINISH);
	}

	digest->schema_version = PQCP_DEPLOYMENT_TRACE_BUILDER_SCHEMA_VERSION;
	digest->line_count = builder->line_count;
	digest->byte_count = builder->length > UINT32_MAX ?
		UINT32_MAX : (uint32_t)builder->length;
	digest->error_mask = builder->error_mask;
	digest_to_hex(builder->digest_words, digest->digest_hex);
	digest->passed = builder->error_mask == 0U &&
			 digest->replay_result.passed;

	return digest->passed ? 0 : (ret != 0 ? ret : -EBADMSG);
}

int pqcp_deployment_trace_digest_emit(
	const struct pqcp_deployment_trace_digest *digest)
{
	if (digest == NULL ||
	    digest->schema_version !=
		    PQCP_DEPLOYMENT_TRACE_BUILDER_SCHEMA_VERSION ||
	    digest->digest_hex[0] == '\0' ||
	    (digest->error_mask &
	     ~PQCP_DEPLOYMENT_TRACE_ERROR_KNOWN_MASK) != 0U ||
	    digest->passed !=
		    (digest->error_mask == 0U &&
		     digest->replay_result.passed)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_TRACE_DIGEST schema=%u lines=%u bytes=%u digest=%s replay=%s\n",
	       digest->schema_version,
	       digest->line_count,
	       digest->byte_count,
	       digest->digest_hex,
	       digest->replay_result.passed ? "PASS" : "FAIL");

	return digest->passed ? 0 : -EBADMSG;
}
