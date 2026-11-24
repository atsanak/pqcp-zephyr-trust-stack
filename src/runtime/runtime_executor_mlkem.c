/*
 * SPDX-License-Identifier: MIT
 *
 * ML-KEM operations for the executable runtime.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <pqcp_zephyr/runtime_executor.h>

#include "runtime_internal.h"

static bool compiled_mlkem_level(uint32_t level)
{
	switch (level) {
	case PQCP_MLKEM_512:
		return IS_ENABLED(CONFIG_PQCP_MLKEM_LEVEL_512);
	case PQCP_MLKEM_768:
		return IS_ENABLED(CONFIG_PQCP_MLKEM_LEVEL_768);
	case PQCP_MLKEM_1024:
		return IS_ENABLED(CONFIG_PQCP_MLKEM_LEVEL_1024);
	default:
		return false;
	}
}

static int ensure_profile_id(
	struct pqcp_runtime_job *job)
{
	if (pqcp_runtime_internal_text_valid(
		    job->profile_id, sizeof(job->profile_id))) {
		return 0;
	}
	return pqcp_runtime_internal_profile_id(
		PQCP_RUNTIME_KEY_MLKEM_KEYPAIR,
		job->level, 0U, job->profile_id);
}

static int shared_secret_request(
	const struct pqcp_runtime_job *job,
	struct pqcp_runtime_key_request *request)
{
	memset(request, 0, sizeof(*request));
	request->family = PQCP_RUNTIME_KEY_SHARED_SECRET;
	request->level = 256U;
	request->usage =
		PQCP_RUNTIME_USAGE_DERIVE |
		PQCP_RUNTIME_USAGE_DESTROY;
	request->now_ms = pqcp_runtime_internal_now_ms();
	request->expires_at_ms =
		job->deadline_ms != 0U ?
		job->deadline_ms :
		request->now_ms + 60000U;
	request->owner = "runtime";
	request->label = "kem-shared";
	request->persistent = false;
	request->exportable_public = false;
	return 0;
}

int pqcp_runtime_execute_mlkem_keygen(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity)
{
	struct pqcp_runtime_key_request request;
	int ret;

	ARG_UNUSED(workspace);
	ARG_UNUSED(workspace_capacity);
	if (executor == NULL || job == NULL ||
	    !compiled_mlkem_level(job->level)) {
		return -ENOTSUP;
	}
	request = job->key_request;
	if (request.family == PQCP_RUNTIME_KEY_NONE) {
		memset(&request, 0, sizeof(request));
		request.family =
			PQCP_RUNTIME_KEY_MLKEM_KEYPAIR;
		request.level = job->level;
		request.usage =
			PQCP_RUNTIME_USAGE_ENCAPSULATE |
			PQCP_RUNTIME_USAGE_DECAPSULATE |
			PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
			PQCP_RUNTIME_USAGE_DESTROY;
		request.now_ms =
			pqcp_runtime_internal_now_ms();
		request.owner = "runtime";
		request.label = "mlkem-keypair";
		request.exportable_public = true;
	}
	if (request.family !=
		    PQCP_RUNTIME_KEY_MLKEM_KEYPAIR ||
	    request.level != job->level) {
		return -EINVAL;
	}
	ret = pqcp_runtime_key_store_generate(
		executor->key_store, &request,
		&job->primary_key);
	if (ret != 0) {
		return ret;
	}
	return ensure_profile_id(job);
}

int pqcp_runtime_execute_mlkem_encapsulate(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity)
{
	size_t ciphertext_length;
	struct pqcp_runtime_key_request secret_request;
	int ret;

	if (executor == NULL || job == NULL ||
	    workspace == NULL ||
	    !compiled_mlkem_level(job->level) ||
	    job->output == NULL) {
		return -EINVAL;
	}
	ciphertext_length = pqcp_mlkem_ct_size(
		(pqcp_mlkem_level_t)job->level);
	if (ciphertext_length == 0U ||
	    workspace_capacity < ciphertext_length ||
	    job->output_capacity < ciphertext_length) {
		return -EINVAL;
	}
	shared_secret_request(job, &secret_request);
	ret = pqcp_runtime_key_store_encapsulate(
		executor->key_store, &job->primary_key,
		&secret_request, workspace,
		workspace_capacity, &ciphertext_length,
		&job->secondary_key);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			workspace, workspace_capacity);
		return ret;
	}
	memcpy(job->output, workspace, ciphertext_length);
	job->output_length = ciphertext_length;
	pqcp_runtime_secure_zero(
		workspace, workspace_capacity);
	return ensure_profile_id(job);
}

int pqcp_runtime_execute_mlkem_decapsulate(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity)
{
	size_t ciphertext_length;
	struct pqcp_runtime_key_request secret_request;
	int ret;

	if (executor == NULL || job == NULL ||
	    workspace == NULL || workspace_capacity == 0U ||
	    !compiled_mlkem_level(job->level) ||
	    job->input == NULL) {
		return -EINVAL;
	}
	ciphertext_length = pqcp_mlkem_ct_size(
		(pqcp_mlkem_level_t)job->level);
	if (ciphertext_length == 0U ||
	    job->input_length != ciphertext_length) {
		return -EINVAL;
	}
	shared_secret_request(job, &secret_request);
	ret = pqcp_runtime_key_store_decapsulate(
		executor->key_store, &job->primary_key,
		job->input, job->input_length,
		&secret_request, &job->secondary_key);
	if (ret != 0) {
		return ret;
	}
	return ensure_profile_id(job);
}
