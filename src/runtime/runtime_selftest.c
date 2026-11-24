/*
 * SPDX-License-Identifier: MIT
 *
 * Executable runtime self-test using stored keys and scheduled operations.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_service.h>

#include "runtime_internal.h"

static int select_profile(
	struct pqcp_runtime_service *service,
	uint32_t mlkem_level,
	uint32_t mldsa_level,
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS])
{
	int ret = pqcp_runtime_internal_profile_id(
		PQCP_RUNTIME_KEY_NONE, mlkem_level,
		mldsa_level, profile_id);

	if (ret != 0) {
		return ret;
	}
	return pqcp_adaptive_profile_registry_find(
		       &service->sessions.adaptive_control->registry,
		       profile_id) != NULL ?
		0 : -ENOENT;
}

static void initialize_job(
	struct pqcp_runtime_job *job,
	uint64_t id,
	uint64_t session_id,
	enum pqcp_runtime_job_type type,
	uint32_t level,
	const char *profile_id)
{
	memset(job, 0, sizeof(*job));
	job->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	job->job_id = id;
	job->session_id = session_id;
	job->type = type;
	job->priority = PQCP_RUNTIME_PRIORITY_CRITICAL;
	job->status = PQCP_RUNTIME_STATUS_IDLE;
	job->flags =
		PQCP_RUNTIME_JOB_FLAG_SYNCHRONOUS |
		PQCP_RUNTIME_JOB_FLAG_ZERO_OUTPUT_ON_FAILURE |
		PQCP_RUNTIME_JOB_FLAG_RECORD_ADAPTIVE_OBSERVATION;
	job->level = level;
	job->deadline_ms =
		pqcp_runtime_internal_now_ms() + 30000U;
	(void)pqcp_runtime_internal_copy_text(
		job->profile_id, sizeof(job->profile_id),
		profile_id);
}

int pqcp_runtime_service_selftest(
	struct pqcp_runtime_service *service,
	uint32_t mlkem_level,
	uint32_t mldsa_level,
	uint64_t now_ms)
{
	static const uint8_t message[] =
		"PQCP executable runtime self-test";
	static const uint8_t confirmation_salt[] =
		"PQCP runtime self-test salt";
	static const uint8_t confirmation_info[] =
		"PQCP runtime self-test AEAD";
	static const uint8_t confirmation_nonce[
		PQCP_RUNTIME_AEAD_NONCE_BYTES] = {
		0x50U, 0x51U, 0x43U, 0x50U,
		0x53U, 0x45U, 0x4cU, 0x46U,
		0x54U, 0x45U, 0x53U, 0x54U,
	};
	uint8_t ciphertext[PQCP_MLKEM_CT_SIZE_MAX];
	uint8_t signature[PQCP_MLDSA_SIG_SIZE_MAX];
	uint8_t confirmation[
		sizeof(message) - 1U +
		PQCP_RUNTIME_AEAD_TAG_BYTES];
	uint8_t recovered[sizeof(message) - 1U];
	struct pqcp_runtime_session_request request;
	struct pqcp_runtime_key_request derived_request = {
		.family = PQCP_RUNTIME_KEY_AEAD,
		.level = 256U,
		.usage = PQCP_RUNTIME_USAGE_ENCRYPT |
			 PQCP_RUNTIME_USAGE_DECRYPT |
			 PQCP_RUNTIME_USAGE_MAC |
			 PQCP_RUNTIME_USAGE_DERIVE |
			 PQCP_RUNTIME_USAGE_DESTROY,
		.owner = "runtime-selftest",
		.label = "kem-confirmation",
		.persistent = false,
		.exportable_public = false,
	};
	struct pqcp_runtime_session *session = NULL;
	struct pqcp_runtime_job job;
	struct pqcp_runtime_key_handle encapsulated_secret = { 0 };
	struct pqcp_runtime_key_handle decapsulated_secret = { 0 };
	struct pqcp_runtime_key_handle encapsulated_aead = { 0 };
	struct pqcp_runtime_key_handle decapsulated_aead = { 0 };
	size_t ciphertext_length = 0U;
	size_t signature_length = 0U;
	size_t confirmation_length = 0U;
	size_t recovered_length = 0U;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	const uint64_t session_id =
		UINT64_C(0x5051435053454c46);
	int ret;

	if (service == NULL || !service->initialized ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = select_profile(
		service, mlkem_level, mldsa_level,
		profile_id);
	if (ret != 0) {
		return ret;
	}
	memset(&request, 0, sizeof(request));
	request.session_id = session_id;
	request.profile_id = profile_id;
	request.now_ms = now_ms;
	request.expires_at_ms = now_ms + 60000U;
	request.generate_kem_key = true;
	request.generate_signing_key = true;
	request.protected_channel = false;
	ret = pqcp_runtime_controller_open_session(
		&service->controller, &request, &session);
	if (ret != 0) {
		return ret;
	}

	initialize_job(
		&job, session_id ^ 1U, session_id,
		PQCP_RUNTIME_JOB_MLKEM_ENCAPSULATE,
		mlkem_level, profile_id);
	job.primary_key = session->kem_key;
	job.output = ciphertext;
	job.output_capacity = sizeof(ciphertext);
	ret = pqcp_runtime_controller_submit(
		&service->controller, session_id, &job);
	if (ret != 0) {
		goto cleanup;
	}
	ciphertext_length = job.output_length;
	encapsulated_secret = job.secondary_key;

	initialize_job(
		&job, session_id ^ 2U, session_id,
		PQCP_RUNTIME_JOB_MLKEM_DECAPSULATE,
		mlkem_level, profile_id);
	job.primary_key = session->kem_key;
	job.input = ciphertext;
	job.input_length = ciphertext_length;
	ret = pqcp_runtime_controller_submit(
		&service->controller, session_id, &job);
	if (ret != 0) {
		goto cleanup;
	}
	decapsulated_secret = job.secondary_key;
	derived_request.now_ms = now_ms;
	derived_request.expires_at_ms = now_ms + 60000U;
	ret = pqcp_runtime_key_store_derive(
		&service->key_store, &encapsulated_secret,
		confirmation_salt,
		sizeof(confirmation_salt) - 1U,
		confirmation_info,
		sizeof(confirmation_info) - 1U,
		&derived_request, &encapsulated_aead);
	if (ret == 0) {
		ret = pqcp_runtime_key_store_derive(
			&service->key_store, &decapsulated_secret,
			confirmation_salt,
			sizeof(confirmation_salt) - 1U,
			confirmation_info,
			sizeof(confirmation_info) - 1U,
			&derived_request, &decapsulated_aead);
	}
	if (ret == 0) {
		ret = pqcp_runtime_key_store_aead_encrypt(
			&service->key_store, &encapsulated_aead,
			confirmation_nonce,
			sizeof(confirmation_nonce), NULL, 0U,
			message, sizeof(message) - 1U,
			confirmation, sizeof(confirmation),
			&confirmation_length);
	}
	if (ret == 0) {
		ret = pqcp_runtime_key_store_aead_decrypt(
			&service->key_store, &decapsulated_aead,
			confirmation_nonce,
			sizeof(confirmation_nonce), NULL, 0U,
			confirmation, confirmation_length,
			recovered, sizeof(recovered),
			&recovered_length);
	}
	if (ret == 0 &&
	    (recovered_length != sizeof(message) - 1U ||
	     memcmp(recovered, message, recovered_length) != 0)) {
		ret = -EKEYREJECTED;
	}
	if (ret != 0) {
		goto cleanup;
	}

	initialize_job(
		&job, session_id ^ 3U, session_id,
		PQCP_RUNTIME_JOB_MLDSA_SIGN,
		mldsa_level, profile_id);
	job.primary_key = session->signing_key;
	job.input = message;
	job.input_length = sizeof(message) - 1U;
	job.context = (const uint8_t *)"runtime-selftest";
	job.context_length = 16U;
	job.output = signature;
	job.output_capacity = sizeof(signature);
	ret = pqcp_runtime_controller_submit(
		&service->controller, session_id, &job);
	if (ret != 0) {
		goto cleanup;
	}
	signature_length = job.output_length;

	initialize_job(
		&job, session_id ^ 4U, session_id,
		PQCP_RUNTIME_JOB_MLDSA_VERIFY,
		mldsa_level, profile_id);
	job.primary_key = session->signing_key;
	job.input = message;
	job.input_length = sizeof(message) - 1U;
	job.aux_input = signature;
	job.aux_input_length = signature_length;
	job.context = (const uint8_t *)"runtime-selftest";
	job.context_length = 16U;
	ret = pqcp_runtime_controller_submit(
		&service->controller, session_id, &job);

cleanup:
	if (pqcp_runtime_key_handle_is_valid(
		    &encapsulated_aead)) {
		(void)pqcp_runtime_key_store_destroy(
			&service->key_store,
			&encapsulated_aead);
	}
	if (pqcp_runtime_key_handle_is_valid(
		    &decapsulated_aead)) {
		(void)pqcp_runtime_key_store_destroy(
			&service->key_store,
			&decapsulated_aead);
	}
	if (pqcp_runtime_key_handle_is_valid(
		    &encapsulated_secret)) {
		(void)pqcp_runtime_key_store_destroy(
			&service->key_store,
			&encapsulated_secret);
	}
	if (pqcp_runtime_key_handle_is_valid(
		    &decapsulated_secret)) {
		(void)pqcp_runtime_key_store_destroy(
			&service->key_store,
			&decapsulated_secret);
	}
	(void)pqcp_runtime_controller_close_session(
		&service->controller, session_id);
	pqcp_runtime_secure_zero(
		confirmation, sizeof(confirmation));
	pqcp_runtime_secure_zero(recovered, sizeof(recovered));
	pqcp_runtime_secure_zero(
		signature, sizeof(signature));
	pqcp_runtime_secure_zero(
		ciphertext, sizeof(ciphertext));
	return ret;
}
