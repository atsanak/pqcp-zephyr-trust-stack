/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Repeated executable runtime measurement campaigns.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_RUNTIME_CAMPAIGN_H_
#define PQCP_ZEPHYR_RUNTIME_CAMPAIGN_H_

#include <pqcp_zephyr/runtime_control.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_RUNTIME_CAMPAIGN_MAX_SAMPLES 128U

struct pqcp_runtime_campaign_config {
	uint32_t schema_version;
	uint32_t warmups;
	uint32_t repetitions;
	uint32_t minimum_success_permille;
	uint32_t maximum_cv_permille;
	enum pqcp_runtime_job_type operation;
	uint32_t level;
	uint64_t session_id;
	uint64_t per_job_timeout_ms;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
};

struct pqcp_runtime_campaign_sample {
	uint32_t schema_version;
	uint32_t index;
	uint64_t latency_us;
	uint64_t cycles;
	uint64_t stack_bytes;
	uint64_t workspace_bytes;
	int result;
	bool warmup;
	bool success;
};

struct pqcp_runtime_campaign_metric {
	uint64_t minimum;
	uint64_t maximum;
	uint64_t mean;
	uint64_t median;
	uint64_t p90;
	uint64_t p99;
	uint64_t mad;
	uint64_t standard_deviation;
	uint32_t coefficient_variation_permille;
};

struct pqcp_runtime_campaign_result {
	uint32_t schema_version;
	enum pqcp_runtime_status status;
	uint32_t sample_count;
	uint32_t successful_samples;
	uint32_t failed_samples;
	uint32_t success_permille;
	uint32_t warning_mask;
	uint32_t blocker_mask;
	struct pqcp_runtime_campaign_metric latency;
	struct pqcp_runtime_campaign_metric cycles;
	struct pqcp_runtime_campaign_metric stack;
	struct pqcp_runtime_campaign_metric workspace;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	char digest_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];
};

typedef int (*pqcp_runtime_campaign_prepare_fn)(
	uint32_t iteration,
	bool warmup,
	struct pqcp_runtime_job *job,
	void *user);

int pqcp_runtime_campaign_run(
	struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_campaign_config *config,
	struct pqcp_runtime_campaign_sample *samples,
	size_t sample_capacity,
	pqcp_runtime_campaign_prepare_fn prepare,
	void *prepare_user,
	struct pqcp_runtime_campaign_result *result);
int pqcp_runtime_campaign_validate(
	const struct pqcp_runtime_campaign_config *config,
	const struct pqcp_runtime_campaign_sample *samples,
	size_t sample_count,
	const struct pqcp_runtime_campaign_result *result);
int pqcp_runtime_campaign_emit(
	const struct pqcp_runtime_campaign_config *config,
	const struct pqcp_runtime_campaign_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_RUNTIME_CAMPAIGN_H_ */
