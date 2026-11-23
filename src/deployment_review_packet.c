/*
 * SPDX-License-Identifier: MIT
 *
 * Firmware-native deployment review packet builder.
 */

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_review_packet.h>

struct packet_builder {
	char *buffer;
	size_t capacity;
	size_t length;
	uint32_t line_count;
	uint32_t error_mask;
	uint64_t digest[4];
};

static bool status_valid(enum pqcp_deployment_review_packet_status status)
{
	return status >= PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL &&
	       status <= PQCP_DEPLOYMENT_REVIEW_PACKET_PASS;
}

const char *pqcp_deployment_review_packet_status_str(
	enum pqcp_deployment_review_packet_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_REVIEW_PACKET_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_REVIEW_PACKET_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL:
		return "FAIL";
	default:
		return "UNKNOWN";
	}
}

static void digest_init(uint64_t digest[4])
{
	digest[0] = 0x6c62272e07bb0142ULL;
	digest[1] = 0x62b821756295c58dULL;
	digest[2] = 0x9e3779b97f4a7c15ULL;
	digest[3] = 0xc2b2ae3d27d4eb4fULL;
}

static uint64_t rotl64(uint64_t value, uint32_t bits)
{
	return (value << bits) | (value >> (64U - bits));
}

static void digest_update_byte(uint64_t digest[4], uint8_t value)
{
	digest[0] ^= value;
	digest[0] *= 0x100000001b3ULL;
	digest[1] += digest[0] + ((uint64_t)value << 11U);
	digest[1] = rotl64(digest[1], 17U) * 0x9e3779b185ebca87ULL;
	digest[2] ^= digest[1] + value + 0x165667b19e3779f9ULL;
	digest[2] = rotl64(digest[2], 31U);
	digest[3] += digest[2] ^ (digest[0] >> 9U);
	digest[3] = rotl64(digest[3], 43U);
}

static void digest_update_line(uint64_t digest[4], const char *line)
{
	for (const char *p = line; *p != '\0'; ++p) {
		digest_update_byte(digest, (uint8_t)*p);
	}
	digest_update_byte(digest, (uint8_t)'\n');
}

static void digest_to_hex(const uint64_t digest[4], char out[
			  PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U])
{
	(void)snprintk(out,
		       PQCP_DEPLOYMENT_REVIEW_PACKET_DIGEST_HEX_CHARS + 1U,
		       "%016llx%016llx%016llx%016llx",
		       (unsigned long long)digest[0],
		       (unsigned long long)digest[1],
		       (unsigned long long)digest[2],
		       (unsigned long long)digest[3]);
}

static int builder_init(struct packet_builder *builder,
			char *buffer,
			size_t capacity)
{
	if (builder == NULL || buffer == NULL || capacity < 2U) {
		return -EINVAL;
	}

	memset(builder, 0, sizeof(*builder));
	memset(buffer, 0, capacity);
	builder->buffer = buffer;
	builder->capacity = capacity;
	digest_init(builder->digest);

	return 0;
}

static int append_line(struct packet_builder *builder, const char *fmt, ...)
{
	char line[PQCP_DEPLOYMENT_REVIEW_PACKET_LINE_MAX];
	va_list args;
	size_t len;
	int written;

	if (builder == NULL || builder->buffer == NULL || fmt == NULL) {
		return -EINVAL;
	}

	va_start(args, fmt);
	written = vsnprintk(line, sizeof(line), fmt, args);
	va_end(args);
	if (written < 0 || written >= (int)sizeof(line)) {
		builder->error_mask |=
			PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_OVERFLOW;
		return -ENOSPC;
	}

	len = strlen(line);
	if (len + 2U > builder->capacity - builder->length) {
		builder->error_mask |=
			PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_OVERFLOW;
		return -ENOSPC;
	}

	memcpy(&builder->buffer[builder->length], line, len);
	builder->length += len;
	builder->buffer[builder->length++] = '\n';
	builder->buffer[builder->length] = '\0';
	builder->line_count++;
	digest_update_line(builder->digest, line);

	return 0;
}

static bool top_ids_match(const char *a, const char *b)
{
	if (a == NULL || b == NULL) {
		return false;
	}

	return strcmp(a, b) == 0;
}

static bool pipeline_status_consistent(
	const struct pqcp_deployment_pipeline_result *pipeline)
{
	return pipeline->passed ==
	       (pipeline->error_mask == 0U &&
		pipeline->recommendation_ready &&
		pipeline->replay_passed &&
		pipeline->appraisal_passed &&
		pipeline->claims_passed);
}

static bool budget_status_consistent(
	const struct pqcp_deployment_budget_report *budget)
{
	if (budget->pass_count + budget->warn_count + budget->fail_count !=
	    budget->candidate_count) {
		return false;
	}
	if (budget->status == PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL) {
		return budget->fail_count != 0U || budget->blocker_mask != 0U;
	}
	if (budget->status == PQCP_DEPLOYMENT_BUDGET_STATUS_WARN) {
		return budget->fail_count == 0U &&
		       budget->blocker_mask == 0U &&
		       (budget->warn_count != 0U || budget->warning_mask != 0U);
	}

	return budget->status == PQCP_DEPLOYMENT_BUDGET_STATUS_PASS &&
	       budget->fail_count == 0U && budget->warn_count == 0U &&
	       budget->blocker_mask == 0U && budget->warning_mask == 0U;
}

static bool experiment_status_consistent(
	const struct pqcp_deployment_experiment_plan *experiments)
{
	if (experiments->blocking_count + experiments->recommended_count !=
	    experiments->row_count) {
		return false;
	}
	if (experiments->status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL) {
		return experiments->blocking_count != 0U ||
		       !experiments->pipeline_passed ||
		       experiments->budget_status ==
			       PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL;
	}
	if (experiments->status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_WARN) {
		return experiments->blocking_count == 0U &&
		       (experiments->recommended_count != 0U ||
			experiments->budget_status ==
				PQCP_DEPLOYMENT_BUDGET_STATUS_WARN);
	}

	return experiments->status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS &&
	       experiments->row_count == 0U;
}

static bool status_inputs_valid(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments)
{
	return pipeline_status_consistent(pipeline) &&
	       budget_status_consistent(budget) &&
	       experiment_status_consistent(experiments);
}

static int validate_inputs(
	const struct pqcp_deployment_pipeline_config *config,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	const char *buffer,
	size_t buffer_size,
	const struct pqcp_deployment_review_packet *packet)
{
	if (config == NULL || pipeline == NULL || budget == NULL ||
	    experiments == NULL || buffer == NULL || packet == NULL ||
	    buffer_size < 2U ||
	    pqcp_deployment_scenario_validate(config->scenario) != 0 ||
	    pipeline->schema_version != PQCP_DEPLOYMENT_PIPELINE_SCHEMA_VERSION ||
	    budget->schema_version != PQCP_DEPLOYMENT_BUDGET_SCHEMA_VERSION ||
	    experiments->schema_version !=
		    PQCP_DEPLOYMENT_EXPERIMENT_PLAN_SCHEMA_VERSION ||
	    pipeline->candidate_count == 0U ||
	    pipeline->candidate_count != budget->candidate_count ||
	    budget->candidate_count > PQCP_DEPLOYMENT_MAX_CANDIDATES ||
	    pipeline->trace_digest.digest_hex[0] == '\0' ||
	    pipeline->top_candidate_id == NULL ||
	    budget->top_candidate_id == NULL ||
	    experiments->top_candidate_id == NULL) {
		return -EINVAL;
	}

	return 0;
}

static uint32_t min3(uint32_t a, uint32_t b, uint32_t c)
{
	uint32_t min = a < b ? a : b;

	return min < c ? min : c;
}

static uint32_t compute_review_score(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments)
{
	uint32_t budget_score = 100U;
	uint32_t experiment_score = 100U;

	if (budget->status == PQCP_DEPLOYMENT_BUDGET_STATUS_WARN) {
		budget_score = 75U;
	} else if (budget->status == PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL) {
		budget_score = 25U;
	}

	if (experiments->status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_WARN) {
		experiment_score = 80U;
	} else if (experiments->status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL) {
		experiment_score = experiments->blocking_count > 0U ? 20U : 40U;
	}

	return min3(pipeline->appraisal.readiness_score, budget_score,
		    experiment_score);
}

static enum pqcp_deployment_review_packet_status compute_status(
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	uint32_t error_mask,
	uint32_t warning_mask)
{
	if (error_mask != 0U || !pipeline->passed ||
	    budget->status == PQCP_DEPLOYMENT_BUDGET_STATUS_FAIL ||
	    experiments->status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_FAIL) {
		return PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL;
	}
	if (warning_mask != 0U ||
	    budget->status == PQCP_DEPLOYMENT_BUDGET_STATUS_WARN ||
	    experiments->status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_WARN) {
		return PQCP_DEPLOYMENT_REVIEW_PACKET_WARN;
	}

	return PQCP_DEPLOYMENT_REVIEW_PACKET_PASS;
}

static uint32_t compute_warnings(
	const struct pqcp_deployment_pipeline_config *config,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_experiment_plan *experiments)
{
	uint32_t warnings = 0U;

	if (experiments->recommended_count != 0U) {
		warnings |=
			PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_OPEN_EXPERIMENTS;
	}
	if (pipeline->appraisal.readiness_score < 80U ||
	    pipeline->claim_matrix.average_score < 80U) {
		warnings |= PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_LOW_SCORE;
	}
	if (!config->scenario->require_hardware_evidence &&
	    pipeline->campaign_summary.projected_candidate_valid &&
	    (pipeline->campaign_summary.projected_candidate.evidence_mask &
	     PQCP_DEPLOYMENT_EVIDENCE_HARDWARE) == 0U) {
		warnings |= PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_LOCAL_ONLY;
	}

	return warnings;
}

static int append_facts(
	struct packet_builder *builder,
	const struct pqcp_deployment_pipeline_config *config,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments)
{
	int ret;

	ret = append_line(
		builder,
		"PQCP_DEPLOYMENT_REVIEW_FACT schema=%u field=scenario id=%s operation=%s target=%s evidence_level=%s hardware_required=%u native_required=%u",
		PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION,
		config->scenario->scenario_id,
		pqcp_deployment_operation_str(config->scenario->operation),
		pqcp_deployment_target_class_str(config->scenario->target_class),
		pqcp_deployment_evidence_level_str(
			config->scenario->required_evidence_level),
		config->scenario->require_hardware_evidence ? 1U : 0U,
		config->scenario->require_native_provider ? 1U : 0U);
	if (ret != 0) {
		return ret;
	}

	ret = append_line(
		builder,
		"PQCP_DEPLOYMENT_REVIEW_FACT schema=%u field=pipeline status=%s errors=0x%08x candidates=%u gaps=%u top=%s top_score=%u replay=%s appraisal=%s claims=%s readiness=%u claim_score=%u trace_digest=%s",
		PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION,
		pipeline->passed ? "PASS" : "FAIL",
		pipeline->error_mask,
		pipeline->candidate_count,
		pipeline->gap_count,
		pipeline->top_candidate_id,
		pipeline->top_candidate_score,
		pipeline->replay_passed ? "PASS" : "FAIL",
		pipeline->appraisal_passed ? "PASS" : "FAIL",
		pipeline->claims_passed ? "PASS" : "FAIL",
		pipeline->appraisal.readiness_score,
		pipeline->claim_matrix.average_score,
		pipeline->trace_digest.digest_hex);
	if (ret != 0) {
		return ret;
	}

	ret = append_line(
		builder,
		"PQCP_DEPLOYMENT_REVIEW_FACT schema=%u field=budget status=%s candidates=%u pass=%u warn=%u fail=%u blockers=0x%08x warnings=0x%08x top=%s top_status=%s top_margin=%u",
		PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION,
		pqcp_deployment_budget_status_str(budget->status),
		budget->candidate_count,
		budget->pass_count,
		budget->warn_count,
		budget->fail_count,
		budget->blocker_mask,
		budget->warning_mask,
		budget->top_candidate_id,
		pqcp_deployment_budget_status_str(budget->top_status),
		budget->top_margin_score);
	if (ret != 0) {
		return ret;
	}

	return append_line(
		builder,
		"PQCP_DEPLOYMENT_REVIEW_FACT schema=%u field=experiments status=%s rows=%u blocking=%u recommended=%u top=%s budget=%s pipeline=%s replay=%s appraisal=%s claims=%s",
		PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION,
		pqcp_deployment_experiment_plan_status_str(experiments->status),
		experiments->row_count,
		experiments->blocking_count,
		experiments->recommended_count,
		experiments->top_candidate_id,
		pqcp_deployment_budget_status_str(experiments->budget_status),
		experiments->pipeline_passed ? "PASS" : "FAIL",
		experiments->replay_passed ? "PASS" : "FAIL",
		experiments->appraisal_passed ? "PASS" : "FAIL",
		experiments->claims_passed ? "PASS" : "FAIL");
}

int pqcp_deployment_review_packet_build(
	const struct pqcp_deployment_pipeline_config *config,
	const struct pqcp_deployment_pipeline_result *pipeline,
	const struct pqcp_deployment_budget_report *budget,
	const struct pqcp_deployment_experiment_plan *experiments,
	char *buffer,
	size_t buffer_size,
	struct pqcp_deployment_review_packet *packet)
{
	struct packet_builder builder;
	uint32_t errors = 0U;
	uint32_t warnings;
	int ret;

	ret = validate_inputs(config, pipeline, budget, experiments, buffer,
			      buffer_size, packet);
	if (ret != 0) {
		if (packet != NULL) {
			memset(packet, 0, sizeof(*packet));
			packet->schema_version =
				PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION;
			packet->status = PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL;
			packet->error_mask =
				PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_INVALID_INPUT;
			packet->top_candidate_id = "none";
		}
		return ret;
	}

	memset(packet, 0, sizeof(*packet));
	packet->schema_version = PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION;
	packet->top_candidate_id = budget->top_candidate_id;
	packet->candidate_count = pipeline->candidate_count;
	packet->experiment_count = experiments->row_count;
	packet->blocking_experiment_count = experiments->blocking_count;
	packet->readiness_score = pipeline->appraisal.readiness_score;
	packet->claim_score = pipeline->claim_matrix.average_score;
	packet->pipeline_passed = pipeline->passed;
	packet->replay_passed = pipeline->replay_passed;
	packet->budget_passed =
		budget->status == PQCP_DEPLOYMENT_BUDGET_STATUS_PASS;
	packet->experiment_plan_passed =
		experiments->status == PQCP_DEPLOYMENT_EXPERIMENT_PLAN_PASS;
	(void)snprintk(packet->trace_digest_hex,
		       sizeof(packet->trace_digest_hex), "%s",
		       pipeline->trace_digest.digest_hex);

	if (!top_ids_match(pipeline->top_candidate_id, budget->top_candidate_id) ||
	    !top_ids_match(budget->top_candidate_id,
			   experiments->top_candidate_id)) {
		errors |= PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_TOP_MISMATCH;
	}
	if (!status_inputs_valid(pipeline, budget, experiments)) {
		errors |= PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_STATUS_MISMATCH;
	}

	ret = builder_init(&builder, buffer, buffer_size);
	if (ret != 0) {
		packet->error_mask =
			errors |
			PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_INVALID_INPUT;
		packet->status = PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL;
		return ret;
	}
	ret = append_facts(&builder, config, pipeline, budget, experiments);
	if (ret != 0) {
		errors |= builder.error_mask;
	}

	packet->line_count = builder.line_count;
	packet->byte_count = builder.length > UINT32_MAX ?
		UINT32_MAX : (uint32_t)builder.length;
	digest_to_hex(builder.digest, packet->packet_digest_hex);
	warnings = compute_warnings(config, pipeline, experiments);
	packet->warning_mask = warnings;
	packet->error_mask = errors;
	packet->review_score =
		compute_review_score(pipeline, budget, experiments);
	packet->status = compute_status(pipeline, budget, experiments, errors,
					warnings);

	if (ret != 0) {
		return ret;
	}

	return errors != 0U ? -EBADMSG : 0;
}

static bool packet_valid(const struct pqcp_deployment_review_packet *packet)
{
	return packet != NULL &&
	       packet->schema_version ==
		       PQCP_DEPLOYMENT_REVIEW_PACKET_SCHEMA_VERSION &&
	       status_valid(packet->status) &&
	       packet->top_candidate_id != NULL &&
	       packet->candidate_count != 0U &&
	       packet->readiness_score <= 100U &&
	       packet->claim_score <= 100U &&
	       packet->review_score <= 100U &&
	       packet->trace_digest_hex[0] != '\0' &&
	       packet->packet_digest_hex[0] != '\0' &&
	       (packet->error_mask &
		~PQCP_DEPLOYMENT_REVIEW_PACKET_ERROR_KNOWN_MASK) == 0U &&
	       (packet->warning_mask &
		~PQCP_DEPLOYMENT_REVIEW_PACKET_WARNING_KNOWN_MASK) == 0U;
}

int pqcp_deployment_review_packet_emit_facts(
	const char *buffer,
	const struct pqcp_deployment_review_packet *packet)
{
	if (buffer == NULL || !packet_valid(packet)) {
		return -EINVAL;
	}
	if (packet->byte_count != strlen(buffer)) {
		return -EBADMSG;
	}

	printk("%s", buffer);
	return 0;
}

int pqcp_deployment_review_packet_emit(
	const struct pqcp_deployment_review_packet *packet)
{
	if (!packet_valid(packet)) {
		return -EINVAL;
	}

	printk("PQCP_DEPLOYMENT_REVIEW_PACKET schema=%u status=%s errors=0x%08x warnings=0x%08x lines=%u bytes=%u digest=%s trace_digest=%s top=%s candidates=%u experiments=%u blocking=%u readiness=%u claim_score=%u review_score=%u pipeline=%s replay=%s budget=%s experiment_plan=%s\n",
	       packet->schema_version,
	       pqcp_deployment_review_packet_status_str(packet->status),
	       packet->error_mask,
	       packet->warning_mask,
	       packet->line_count,
	       packet->byte_count,
	       packet->packet_digest_hex,
	       packet->trace_digest_hex,
	       packet->top_candidate_id,
	       packet->candidate_count,
	       packet->experiment_count,
	       packet->blocking_experiment_count,
	       packet->readiness_score,
	       packet->claim_score,
	       packet->review_score,
	       packet->pipeline_passed ? "PASS" : "FAIL",
	       packet->replay_passed ? "PASS" : "FAIL",
	       packet->budget_passed ? "PASS" : "FAIL",
	       packet->experiment_plan_passed ? "PASS" : "FAIL");

	return packet->status == PQCP_DEPLOYMENT_REVIEW_PACKET_FAIL ?
		-EBADMSG : 0;
}
