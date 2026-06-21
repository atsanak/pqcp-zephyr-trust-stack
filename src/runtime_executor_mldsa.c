/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * ML-DSA operations for the executable runtime.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_executor.h>

#include "runtime_internal.h"

static bool compiled_mldsa_level(uint32_t level)
{
	switch (level) {
	case PQCP_MLDSA_44:
		return IS_ENABLED(CONFIG_PQCP_MLDSA_LEVEL_44);
	case PQCP_MLDSA_65:
		return IS_ENABLED(CONFIG_PQCP_MLDSA_LEVEL_65);
	case PQCP_MLDSA_87:
		return IS_ENABLED(CONFIG_PQCP_MLDSA_LEVEL_87);
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
		PQCP_RUNTIME_KEY_MLDSA_KEYPAIR,
		0U, job->level, job->profile_id);
}

int pqcp_runtime_execute_mldsa_keygen(
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
	    !compiled_mldsa_level(job->level)) {
		return -ENOTSUP;
	}
	request = job->key_request;
	if (request.family == PQCP_RUNTIME_KEY_NONE) {
		memset(&request, 0, sizeof(request));
		request.family =
			PQCP_RUNTIME_KEY_MLDSA_KEYPAIR;
		request.level = job->level;
		request.usage =
			PQCP_RUNTIME_USAGE_SIGN |
			PQCP_RUNTIME_USAGE_VERIFY |
			PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
			PQCP_RUNTIME_USAGE_DESTROY;
		request.now_ms =
			pqcp_runtime_internal_now_ms();
		request.owner = "runtime";
		request.label = "mldsa-identity";
		request.exportable_public = true;
	}
	if (request.family !=
		    PQCP_RUNTIME_KEY_MLDSA_KEYPAIR ||
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

int pqcp_runtime_execute_mldsa_sign(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity)
{
	size_t signature_length;
	int ret;

	if (executor == NULL || job == NULL ||
	    workspace == NULL ||
	    !compiled_mldsa_level(job->level) ||
	    job->output == NULL ||
	    (job->input == NULL &&
	     job->input_length != 0U)) {
		return -EINVAL;
	}
	signature_length = pqcp_mldsa_sig_size(
		(pqcp_mldsa_level_t)job->level);
	if (signature_length == 0U ||
	    workspace_capacity < signature_length ||
	    job->output_capacity < signature_length) {
		return -EINVAL;
	}
	ret = pqcp_runtime_key_store_sign(
		executor->key_store, &job->primary_key,
		job->input, job->input_length, job->context,
		job->context_length, workspace,
		workspace_capacity, &signature_length);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			workspace, workspace_capacity);
		return ret;
	}
	memcpy(job->output, workspace, signature_length);
	job->output_length = signature_length;
	pqcp_runtime_secure_zero(
		workspace, workspace_capacity);
	return ensure_profile_id(job);
}

int pqcp_runtime_execute_mldsa_verify(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity)
{
	size_t signature_length;
	int ret;

	ARG_UNUSED(workspace);
	ARG_UNUSED(workspace_capacity);
	if (executor == NULL || job == NULL ||
	    !compiled_mldsa_level(job->level) ||
	    (job->input == NULL &&
	     job->input_length != 0U) ||
	    job->aux_input == NULL) {
		return -EINVAL;
	}
	signature_length = pqcp_mldsa_sig_size(
		(pqcp_mldsa_level_t)job->level);
	if (signature_length == 0U ||
	    job->aux_input_length != signature_length) {
		return -EINVAL;
	}
	ret = pqcp_runtime_key_store_verify(
		executor->key_store, &job->primary_key,
		job->input, job->input_length, job->context,
		job->context_length, job->aux_input,
		job->aux_input_length);
	if (ret != 0) {
		return ret;
	}
	return ensure_profile_id(job);
}
