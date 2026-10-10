/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Handle-only HKDF and AES-GCM operations for the executable runtime.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_executor.h>

#include "runtime_internal.h"

static int derived_key_request(
	const struct pqcp_runtime_job *job,
	struct pqcp_runtime_key_request *request)
{
	*request = job->key_request;
	if (request->family == PQCP_RUNTIME_KEY_NONE) {
		memset(request, 0, sizeof(*request));
		request->family = PQCP_RUNTIME_KEY_AEAD;
		request->level = 256U;
		request->usage =
			PQCP_RUNTIME_USAGE_ENCRYPT |
			PQCP_RUNTIME_USAGE_DECRYPT |
			PQCP_RUNTIME_USAGE_MAC |
			PQCP_RUNTIME_USAGE_DERIVE |
			PQCP_RUNTIME_USAGE_DESTROY;
		request->now_ms =
			pqcp_runtime_internal_now_ms();
		request->expires_at_ms =
			job->deadline_ms != 0U ?
			job->deadline_ms :
			request->now_ms + 60000U;
		request->owner = "runtime";
		request->label = "hkdf-aead";
		request->persistent =
			job->primary_key.backend ==
			PQCP_RUNTIME_KEY_BACKEND_PSA_PERSISTENT;
		request->exportable_public = false;
	}
	if (request->family != PQCP_RUNTIME_KEY_AEAD ||
	    (request->level != 0U && request->level != 256U)) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_runtime_execute_hkdf_derive(
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
	    job->primary_key.family !=
		    PQCP_RUNTIME_KEY_SHARED_SECRET) {
		return -EINVAL;
	}
	ret = derived_key_request(job, &request);
	if (ret != 0) {
		return ret;
	}
	return pqcp_runtime_key_store_derive(
		executor->key_store, &job->primary_key,
		job->input, job->input_length,
		job->context, job->context_length,
		&request, &job->secondary_key);
}

static int execute_aead(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	bool encrypt)
{
	if (executor == NULL || job == NULL ||
	    job->primary_key.family != PQCP_RUNTIME_KEY_AEAD ||
	    job->context == NULL ||
	    job->context_length !=
		    PQCP_RUNTIME_AEAD_NONCE_BYTES ||
	    job->input == NULL || job->output == NULL) {
		return -EINVAL;
	}
	if (encrypt) {
		if (job->output_capacity <
		    job->input_length +
			    PQCP_RUNTIME_AEAD_TAG_BYTES) {
			return -ENOSPC;
		}
		return pqcp_runtime_key_store_aead_encrypt(
			executor->key_store, &job->primary_key,
			job->context, job->context_length,
			job->aux_input, job->aux_input_length,
			job->input, job->input_length,
			job->output, job->output_capacity,
			&job->output_length);
	}
	if (job->input_length < PQCP_RUNTIME_AEAD_TAG_BYTES) {
		return -EBADMSG;
	}
	return pqcp_runtime_key_store_aead_decrypt(
		executor->key_store, &job->primary_key,
		job->context, job->context_length,
		job->aux_input, job->aux_input_length,
		job->input, job->input_length,
		job->output, job->output_capacity,
		&job->output_length);
}

int pqcp_runtime_execute_aead_encrypt(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity)
{
	ARG_UNUSED(workspace);
	ARG_UNUSED(workspace_capacity);
	return execute_aead(executor, job, true);
}

int pqcp_runtime_execute_aead_decrypt(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity)
{
	ARG_UNUSED(workspace);
	ARG_UNUSED(workspace_capacity);
	return execute_aead(executor, job, false);
}
