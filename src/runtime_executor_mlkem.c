/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
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

static int acquire_public_key(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	const uint8_t **public_key,
	size_t *public_key_length)
{
	const uint8_t *secret = NULL;
	size_t secret_length = 0U;
	int ret;

	ret = pqcp_runtime_key_store_acquire(
		executor->key_store, &job->primary_key,
		PQCP_RUNTIME_USAGE_ENCAPSULATE,
		pqcp_runtime_internal_now_ms(),
		public_key, public_key_length,
		&secret, &secret_length);
	if (ret != 0) {
		return ret;
	}
	if (*public_key == NULL ||
	    *public_key_length !=
		    pqcp_mlkem_pk_size(
			    (pqcp_mlkem_level_t)job->level)) {
		(void)pqcp_runtime_key_store_release(
			executor->key_store,
			&job->primary_key);
		return -EBADMSG;
	}
	return 0;
}

int pqcp_runtime_execute_mlkem_encapsulate(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity)
{
	const uint8_t *public_key = NULL;
	size_t public_key_length = 0U;
	size_t ciphertext_length;
	struct pqcp_runtime_key_request secret_request;
	uint8_t *ciphertext;
	uint8_t *shared_secret;
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
	    workspace_capacity <
		    ciphertext_length + PQCP_MLKEM_SS_SIZE ||
	    job->output_capacity < ciphertext_length) {
		return -EINVAL;
	}
	ret = acquire_public_key(
		executor, job, &public_key,
		&public_key_length);
	if (ret != 0) {
		return ret;
	}
	ciphertext = workspace;
	shared_secret = workspace + ciphertext_length;
	ret = pqcp_mlkem_encapsulate(
		(pqcp_mlkem_level_t)job->level,
		public_key, ciphertext, shared_secret);
	(void)pqcp_runtime_key_store_release(
		executor->key_store, &job->primary_key);
	if (ret != PQCP_MLKEM_SUCCESS) {
		pqcp_runtime_secure_zero(
			workspace, workspace_capacity);
		return -EIO;
	}
	shared_secret_request(job, &secret_request);
	ret = pqcp_runtime_key_store_create(
		executor->key_store, &secret_request,
		NULL, 0U, shared_secret,
		PQCP_MLKEM_SS_SIZE, &job->secondary_key);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			workspace, workspace_capacity);
		return ret;
	}
	memcpy(job->output, ciphertext, ciphertext_length);
	job->output_length = ciphertext_length;
	pqcp_runtime_secure_zero(
		shared_secret, PQCP_MLKEM_SS_SIZE);
	return ensure_profile_id(job);
}

static int acquire_secret_key(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	const uint8_t **secret_key,
	size_t *secret_key_length)
{
	const uint8_t *public_key = NULL;
	size_t public_key_length = 0U;
	int ret;

	ret = pqcp_runtime_key_store_acquire(
		executor->key_store, &job->primary_key,
		PQCP_RUNTIME_USAGE_DECAPSULATE,
		pqcp_runtime_internal_now_ms(),
		&public_key, &public_key_length,
		secret_key, secret_key_length);
	if (ret != 0) {
		return ret;
	}
	if (*secret_key == NULL ||
	    *secret_key_length !=
		    pqcp_mlkem_sk_size(
			    (pqcp_mlkem_level_t)job->level)) {
		(void)pqcp_runtime_key_store_release(
			executor->key_store,
			&job->primary_key);
		return -EBADMSG;
	}
	return 0;
}

int pqcp_runtime_execute_mlkem_decapsulate(
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_job *job,
	uint8_t *workspace,
	size_t workspace_capacity)
{
	const uint8_t *secret_key = NULL;
	size_t secret_key_length = 0U;
	size_t ciphertext_length;
	struct pqcp_runtime_key_request secret_request;
	int ret;

	if (executor == NULL || job == NULL ||
	    workspace == NULL ||
	    workspace_capacity < PQCP_MLKEM_SS_SIZE ||
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
	ret = acquire_secret_key(
		executor, job, &secret_key,
		&secret_key_length);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_mlkem_decapsulate(
		(pqcp_mlkem_level_t)job->level,
		job->input, secret_key, workspace);
	(void)pqcp_runtime_key_store_release(
		executor->key_store, &job->primary_key);
	if (ret != PQCP_MLKEM_SUCCESS) {
		pqcp_runtime_secure_zero(
			workspace, workspace_capacity);
		return -EIO;
	}
	shared_secret_request(job, &secret_request);
	ret = pqcp_runtime_key_store_create(
		executor->key_store, &secret_request,
		NULL, 0U, workspace,
		PQCP_MLKEM_SS_SIZE, &job->secondary_key);
	pqcp_runtime_secure_zero(
		workspace, workspace_capacity);
	if (ret != 0) {
		return ret;
	}
	return ensure_profile_id(job);
}
