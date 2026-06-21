/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Opaque key operation dispatch and idempotent broker transaction execution.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/crypto_broker.h>
#include <pqcp_zephyr/errno.h>

#include "crypto_broker_internal.h"
#include "runtime_internal.h"

static void key_request_from_spec(
	const struct pqcp_crypto_broker_key_spec *spec,
	const char *owner,
	uint64_t now_ms,
	struct pqcp_runtime_key_request *request)
{
	memset(request, 0, sizeof(*request));
	request->family = spec->family;
	request->level = spec->level;
	request->usage = spec->usage;
	request->now_ms = now_ms;
	request->expires_at_ms = spec->expires_at_ms;
	request->owner = owner;
	request->label = spec->label;
	request->persistent = spec->persistent;
	request->exportable_public =
		spec->exportable_public;
}

static void shared_secret_request(
	const struct pqcp_crypto_broker_request *request,
	const char *owner,
	struct pqcp_runtime_key_request *secret_request)
{
	memset(secret_request, 0, sizeof(*secret_request));
	secret_request->family =
		PQCP_RUNTIME_KEY_SHARED_SECRET;
	secret_request->level = 256U;
	secret_request->usage =
		PQCP_RUNTIME_USAGE_DERIVE |
		PQCP_RUNTIME_USAGE_DESTROY;
	secret_request->now_ms = request->submitted_at_ms;
	secret_request->expires_at_ms = request->deadline_ms;
	secret_request->owner = owner;
	secret_request->label = "broker-kem-secret";
	secret_request->persistent = false;
	secret_request->exportable_public = false;
}

static int copy_output(
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response,
	const uint8_t *output,
	size_t output_length)
{
	if (output_length >
		    sizeof(transaction->output) ||
	    (output == NULL && output_length != 0U)) {
		return -ENOSPC;
	}
	if (response->output != NULL &&
	    response->output_capacity < output_length) {
		return -ENOSPC;
	}
	if (output_length != 0U) {
		memcpy(transaction->output, output,
		       output_length);
		if (response->output != NULL) {
			memcpy(response->output, output,
			       output_length);
		}
	}
	transaction->output_length = output_length;
	response->output_length = output_length;
	return 0;
}

static int dispatch_generate(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const char *owner,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	struct pqcp_runtime_key_request key_request;
	struct pqcp_runtime_key_handle handle = { 0 };
	int ret;

	key_request_from_spec(
		&request->key_spec, owner,
		request->submitted_at_ms, &key_request);
	ret = pqcp_runtime_key_store_generate(
		broker->config.key_store, &key_request, &handle);
	if (ret == 0) {
		transaction->primary_key = handle;
		response->primary_key = handle;
		ret = pqcp_runtime_key_store_metadata(
			broker->config.key_store, &handle,
			&transaction->metadata);
		response->metadata = transaction->metadata;
	}
	if (ret != 0 &&
	    pqcp_runtime_key_handle_is_valid(&handle)) {
		(void)pqcp_runtime_key_store_destroy(
			broker->config.key_store, &handle);
	}
	return ret;
}

static int dispatch_export_public(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	uint8_t output[PQCP_RUNTIME_MAX_PUBLIC_KEY_BYTES];
	size_t output_length = 0U;
	int ret;

	ret = pqcp_runtime_key_store_export_public(
		broker->config.key_store, &request->primary_key,
		output, sizeof(output), &output_length);
	if (ret == 0) {
		ret = copy_output(
			transaction, response, output,
			output_length);
	}
	pqcp_runtime_secure_zero(output, sizeof(output));
	return ret;
}

static int dispatch_sign(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	uint8_t signature[PQCP_MLDSA_SIG_SIZE_MAX];
	size_t signature_length = 0U;
	int ret;

	ret = pqcp_runtime_key_store_sign(
		broker->config.key_store, &request->primary_key,
		request->input, request->input_length,
		request->context, request->context_length,
		signature, sizeof(signature), &signature_length);
	if (ret == 0) {
		ret = copy_output(
			transaction, response, signature,
			signature_length);
	}
	pqcp_runtime_secure_zero(
		signature, sizeof(signature));
	return ret;
}

static int dispatch_verify(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request)
{
	return pqcp_runtime_key_store_verify(
		broker->config.key_store, &request->primary_key,
		request->input, request->input_length,
		request->context, request->context_length,
		request->aux_input, request->aux_input_length);
}

static int dispatch_encapsulate(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const char *owner,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	struct pqcp_runtime_key_request secret_request;
	struct pqcp_runtime_key_handle secret = { 0 };
	uint8_t ciphertext[PQCP_MLKEM_CT_SIZE_MAX];
	size_t ciphertext_length = 0U;
	int ret;

	shared_secret_request(request, owner, &secret_request);
	ret = pqcp_runtime_key_store_encapsulate(
		broker->config.key_store, &request->primary_key,
		&secret_request, ciphertext, sizeof(ciphertext),
		&ciphertext_length, &secret);
	if (ret == 0) {
		ret = copy_output(
			transaction, response, ciphertext,
			ciphertext_length);
	}
	if (ret == 0) {
		transaction->secondary_key = secret;
		response->secondary_key = secret;
	} else if (pqcp_runtime_key_handle_is_valid(&secret)) {
		(void)pqcp_runtime_key_store_destroy(
			broker->config.key_store, &secret);
	}
	pqcp_runtime_secure_zero(
		ciphertext, sizeof(ciphertext));
	return ret;
}

static int dispatch_decapsulate(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const char *owner,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	struct pqcp_runtime_key_request secret_request;
	struct pqcp_runtime_key_handle secret = { 0 };
	int ret;

	shared_secret_request(request, owner, &secret_request);
	ret = pqcp_runtime_key_store_decapsulate(
		broker->config.key_store, &request->primary_key,
		request->input, request->input_length,
		&secret_request, &secret);
	if (ret == 0) {
		transaction->secondary_key = secret;
		response->secondary_key = secret;
	}
	return ret;
}

static int dispatch_derive(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const char *owner,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	struct pqcp_runtime_key_request key_request;
	struct pqcp_runtime_key_handle derived = { 0 };
	int ret;

	key_request_from_spec(
		&request->key_spec, owner,
		request->submitted_at_ms, &key_request);
	ret = pqcp_runtime_key_store_derive(
		broker->config.key_store, &request->primary_key,
		request->input, request->input_length,
		request->aux_input, request->aux_input_length,
		&key_request, &derived);
	if (ret == 0) {
		transaction->primary_key = derived;
		response->primary_key = derived;
		ret = pqcp_runtime_key_store_metadata(
			broker->config.key_store, &derived,
			&transaction->metadata);
		response->metadata = transaction->metadata;
	}
	if (ret != 0 &&
	    pqcp_runtime_key_handle_is_valid(&derived)) {
		(void)pqcp_runtime_key_store_destroy(
			broker->config.key_store, &derived);
	}
	return ret;
}

static int dispatch_mac(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	uint8_t tag[PQCP_RUNTIME_DIGEST_BYTES];
	size_t tag_length = 0U;
	int ret;

	ret = pqcp_runtime_key_store_mac(
		broker->config.key_store, &request->primary_key,
		request->input, request->input_length,
		tag, sizeof(tag), &tag_length);
	if (ret == 0) {
		ret = copy_output(
			transaction, response, tag, tag_length);
	}
	pqcp_runtime_secure_zero(tag, sizeof(tag));
	return ret;
}

static int dispatch_aead(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response,
	bool encrypt)
{
	uint8_t output[PQCP_RUNTIME_MAX_OUTPUT_BYTES];
	size_t output_length = 0U;
	int ret;

	if (encrypt) {
		ret = pqcp_runtime_key_store_aead_encrypt(
			broker->config.key_store,
			&request->primary_key,
			request->aux_input,
			request->aux_input_length,
			request->context,
			request->context_length,
			request->input, request->input_length,
			output, sizeof(output), &output_length);
	} else {
		ret = pqcp_runtime_key_store_aead_decrypt(
			broker->config.key_store,
			&request->primary_key,
			request->aux_input,
			request->aux_input_length,
			request->context,
			request->context_length,
			request->input, request->input_length,
			output, sizeof(output), &output_length);
	}
	if (ret == 0) {
		ret = copy_output(
			transaction, response, output,
			output_length);
	}
	pqcp_runtime_secure_zero(output, sizeof(output));
	return ret;
}

static int dispatch_rotate(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const char *owner,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	struct pqcp_runtime_key_request key_request;
	struct pqcp_runtime_key_handle rotated = { 0 };
	int ret;

	key_request_from_spec(
		&request->key_spec, owner,
		request->submitted_at_ms, &key_request);
	ret = pqcp_runtime_key_store_rotate(
		broker->config.key_store, &request->primary_key,
		&key_request, &rotated);
	if (ret == 0) {
		transaction->primary_key = rotated;
		response->primary_key = rotated;
		ret = pqcp_runtime_key_store_metadata(
			broker->config.key_store, &rotated,
			&transaction->metadata);
		response->metadata = transaction->metadata;
	}
	return ret;
}

static int dispatch_destroy(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request)
{
	return pqcp_runtime_key_store_destroy(
		broker->config.key_store, &request->primary_key);
}

static int dispatch_metadata(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	int ret = pqcp_runtime_key_store_metadata(
		broker->config.key_store, &request->primary_key,
		&transaction->metadata);

	if (ret == 0) {
		response->metadata = transaction->metadata;
	}
	return ret;
}

int pqcp_crypto_broker_internal_dispatch(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const struct pqcp_crypto_broker_authorization *authorization,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response)
{
	const char *owner;

	if (broker == NULL || request == NULL ||
	    authorization == NULL || transaction == NULL ||
	    response == NULL ||
	    authorization->decision !=
		    PQCP_CRYPTO_BROKER_DECISION_ALLOW ||
	    authorization->principal_index >=
		    broker->storage.principal_capacity) {
		return -EINVAL;
	}
	owner = broker->storage.principals[
		authorization->principal_index].id;
	switch (request->operation) {
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_GENERATE:
		return dispatch_generate(
			broker, request, owner,
			transaction, response);
	case PQCP_CRYPTO_BROKER_OPERATION_EXPORT_PUBLIC:
		return dispatch_export_public(
			broker, request, transaction, response);
	case PQCP_CRYPTO_BROKER_OPERATION_SIGN:
		return dispatch_sign(
			broker, request, transaction, response);
	case PQCP_CRYPTO_BROKER_OPERATION_VERIFY:
		return dispatch_verify(broker, request);
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_ENCAPSULATE:
		return dispatch_encapsulate(
			broker, request, owner,
			transaction, response);
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_DECAPSULATE:
		return dispatch_decapsulate(
			broker, request, owner,
			transaction, response);
	case PQCP_CRYPTO_BROKER_OPERATION_HKDF_DERIVE:
		return dispatch_derive(
			broker, request, owner,
			transaction, response);
	case PQCP_CRYPTO_BROKER_OPERATION_MAC:
		return dispatch_mac(
			broker, request, transaction, response);
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_ENCRYPT:
		return dispatch_aead(
			broker, request, transaction, response, true);
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_DECRYPT:
		return dispatch_aead(
			broker, request, transaction, response, false);
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_ROTATE:
		return dispatch_rotate(
			broker, request, owner,
			transaction, response);
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_DESTROY:
		return dispatch_destroy(broker, request);
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_METADATA:
		return dispatch_metadata(
			broker, request, transaction, response);
	default:
		return -ENOTSUP;
	}
}

void pqcp_crypto_broker_internal_destroy_response_keys(
	struct pqcp_crypto_broker *broker,
	struct pqcp_crypto_broker_response *response)
{
	if (broker == NULL || response == NULL) {
		return;
	}
	if (pqcp_runtime_key_handle_is_valid(
		    &response->primary_key)) {
		(void)pqcp_runtime_key_store_destroy(
			broker->config.key_store,
			&response->primary_key);
		memset(&response->primary_key, 0,
		       sizeof(response->primary_key));
	}
	if (pqcp_runtime_key_handle_is_valid(
		    &response->secondary_key)) {
		(void)pqcp_runtime_key_store_destroy(
			broker->config.key_store,
			&response->secondary_key);
		memset(&response->secondary_key, 0,
		       sizeof(response->secondary_key));
	}
}

static bool terminal_state(
	enum pqcp_crypto_broker_transaction_state state)
{
	return state ==
		       PQCP_CRYPTO_BROKER_TRANSACTION_COMPLETED ||
	       state ==
		       PQCP_CRYPTO_BROKER_TRANSACTION_CANCELLED ||
	       state ==
		       PQCP_CRYPTO_BROKER_TRANSACTION_FAILED;
}

static bool creates_key(
	enum pqcp_crypto_broker_operation operation)
{
	switch (operation) {
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_GENERATE:
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_ENCAPSULATE:
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_DECAPSULATE:
	case PQCP_CRYPTO_BROKER_OPERATION_HKDF_DERIVE:
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_ROTATE:
		return true;
	default:
		return false;
	}
}

static uint32_t created_key_count(
	const struct pqcp_crypto_broker_response *response)
{
	uint32_t count = 0U;

	if (pqcp_runtime_key_handle_is_valid(
		    &response->primary_key)) {
		count++;
	}
	if (pqcp_runtime_key_handle_is_valid(
		    &response->secondary_key)) {
		count++;
	}
	return count;
}

static int prepare_transaction(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const struct pqcp_crypto_broker_authorization *authorization,
	const uint8_t request_digest[PQCP_RUNTIME_DIGEST_BYTES],
	uint64_t now_ms,
	struct pqcp_crypto_broker_transaction **transaction)
{
	struct pqcp_crypto_broker_principal *principal;
	struct pqcp_crypto_broker_grant *grant;
	struct pqcp_crypto_broker_capability *capability;
	int index;
	int ret;

	index = pqcp_crypto_broker_internal_free_transaction(
		broker, now_ms);
	if (index < 0) {
		return -ENOSPC;
	}
	if (broker->storage.transactions[index].state !=
	    PQCP_CRYPTO_BROKER_TRANSACTION_EMPTY) {
		pqcp_runtime_secure_zero(
			&broker->storage.transactions[index],
			sizeof(broker->storage.transactions[index]));
	}
	principal = &broker->storage.principals[
		authorization->principal_index];
	grant = &broker->storage.grants[
		authorization->grant_index];
	capability = &broker->storage.capabilities[
		authorization->capability_index];
	ret = pqcp_crypto_broker_internal_reserve_quota(
		principal, request, authorization->cost_units,
		now_ms);
	if (ret != 0) {
		return ret;
	}
	*transaction =
		&broker->storage.transactions[index];
	memset(*transaction, 0, sizeof(**transaction));
	(*transaction)->schema_version =
		PQCP_CRYPTO_BROKER_SCHEMA_VERSION;
	(*transaction)->generation =
		pqcp_crypto_broker_internal_next_generation(
			&broker->next_transaction_generation);
	(*transaction)->principal_index =
		authorization->principal_index;
	memcpy((*transaction)->request_id,
	       request->request_id,
	       sizeof((*transaction)->request_id));
	memcpy((*transaction)->request_digest,
	       request_digest,
	       sizeof((*transaction)->request_digest));
	(*transaction)->state =
		PQCP_CRYPTO_BROKER_TRANSACTION_RUNNING;
	(*transaction)->operation = request->operation;
	(*transaction)->accepted_at_ms = now_ms;
	(*transaction)->job_id = broker->next_job_id++;
	if ((*transaction)->job_id == 0U) {
		(*transaction)->job_id = broker->next_job_id++;
	}
	capability->use_count++;
	if (capability->use_count >= capability->maximum_uses) {
		capability->state =
			PQCP_CRYPTO_BROKER_CAPABILITY_EXHAUSTED;
	}
	grant->use_count++;
	if (grant->use_count >= grant->maximum_uses) {
		grant->state =
			PQCP_CRYPTO_BROKER_GRANT_EXHAUSTED;
	}
	broker->accepted_requests++;
	return 0;
}

static void finish_transaction(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const struct pqcp_crypto_broker_authorization *authorization,
	struct pqcp_crypto_broker_transaction *transaction,
	struct pqcp_crypto_broker_response *response,
	int dispatch_result,
	uint64_t completed_at_ms)
{
	struct pqcp_crypto_broker_principal *principal =
		&broker->storage.principals[
			authorization->principal_index];
	bool cancelled =
		transaction->state ==
			PQCP_CRYPTO_BROKER_TRANSACTION_CANCEL_REQUESTED;

	if (cancelled) {
		pqcp_crypto_broker_internal_destroy_response_keys(
			broker, response);
		pqcp_runtime_secure_zero(
			transaction->output,
			sizeof(transaction->output));
		transaction->output_length = 0U;
		transaction->primary_key =
			(struct pqcp_runtime_key_handle){ 0 };
		transaction->secondary_key =
			(struct pqcp_runtime_key_handle){ 0 };
		transaction->result = -ECANCELED;
		transaction->state =
			PQCP_CRYPTO_BROKER_TRANSACTION_CANCELLED;
		response->result = -ECANCELED;
		response->cancelled = true;
		broker->cancelled_requests++;
	} else if (dispatch_result == 0) {
		transaction->result = 0;
		transaction->state =
			PQCP_CRYPTO_BROKER_TRANSACTION_COMPLETED;
		response->result = 0;
		if (creates_key(request->operation)) {
			const uint32_t created =
				created_key_count(response);

			if (UINT32_MAX -
				    principal->usage.active_keys >=
			    created) {
				principal->usage.active_keys +=
					created;
			}
		}
		if (request->operation ==
			    PQCP_CRYPTO_BROKER_OPERATION_KEY_DESTROY &&
		    principal->usage.active_keys != 0U) {
			principal->usage.active_keys--;
		}
	} else {
		transaction->result = dispatch_result;
		transaction->state =
			PQCP_CRYPTO_BROKER_TRANSACTION_FAILED;
		response->result = dispatch_result;
		if ((request->flags &
		     PQCP_CRYPTO_BROKER_REQUEST_ZERO_OUTPUT_ON_FAILURE) !=
		    0U) {
			pqcp_runtime_secure_zero(
				transaction->output,
				sizeof(transaction->output));
			transaction->output_length = 0U;
			if (response->output != NULL) {
				pqcp_runtime_secure_zero(
					response->output,
					response->output_capacity);
			}
			response->output_length = 0U;
		}
	}
	transaction->completed_at_ms = completed_at_ms;
	pqcp_crypto_broker_internal_complete_quota(
		principal, transaction->output_length, cancelled);
	if (principal->usage.output_bytes >
	    principal->quota.maximum_output_bytes_per_window) {
		principal->state =
			PQCP_CRYPTO_BROKER_PRINCIPAL_SUSPENDED;
		principal->suspended_at_ms = completed_at_ms;
	}
}

int pqcp_crypto_broker_execute(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	struct pqcp_crypto_broker_response *response)
{
	struct pqcp_crypto_broker_authorization authorization;
	struct pqcp_crypto_broker_transaction *transaction = NULL;
	uint8_t request_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint64_t now_ms;
	int principal_index;
	int transaction_index;
	int dispatch_result;
	int ret;

	if (broker == NULL || !broker->initialized ||
	    response == NULL) {
		return -EINVAL;
	}
	uint8_t *caller_output = response->output;
	const size_t caller_output_capacity =
		response->output_capacity;

	memset(response, 0, sizeof(*response));
	response->output = caller_output;
	response->output_capacity = caller_output_capacity;
	ret = pqcp_crypto_broker_internal_validate_request(
		request);
	if (ret != 0) {
		response->result = ret;
		return ret;
	}
	now_ms = pqcp_runtime_internal_now_ms();
	if (now_ms == 0U) {
		now_ms = request->submitted_at_ms;
	}
	ret = pqcp_crypto_broker_internal_request_digest(
		request, request_digest);
	if (ret != 0) {
		response->result = ret;
		return ret;
	}
	ret = pqcp_crypto_broker_authorize(
		broker, request, now_ms, &authorization);
	if (ret != 0) {
		response->result = ret;
		broker->rejected_requests++;
		pqcp_runtime_secure_zero(
			request_digest, sizeof(request_digest));
		return ret;
	}
	ret = k_mutex_lock(&broker->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			request_digest, sizeof(request_digest));
		return ret;
	}
	principal_index = (int)authorization.principal_index;
	transaction_index =
		pqcp_crypto_broker_internal_transaction_index(
			broker, (uint32_t)principal_index,
			request->request_id);
	if (transaction_index >= 0) {
		transaction =
			&broker->storage.transactions[
				transaction_index];
		if (!pqcp_crypto_broker_internal_secure_equal(
			    transaction->request_digest,
			    request_digest,
			    sizeof(request_digest))) {
			broker->rejected_requests++;
			(void)k_mutex_unlock(&broker->lock);
			pqcp_runtime_secure_zero(
				request_digest,
				sizeof(request_digest));
			response->result = -EKEYREJECTED;
			return -EKEYREJECTED;
		}
		if (!terminal_state(transaction->state)) {
			(void)k_mutex_unlock(&broker->lock);
			pqcp_runtime_secure_zero(
				request_digest,
				sizeof(request_digest));
			response->result = -EINPROGRESS;
			return -EINPROGRESS;
		}
		ret =
			pqcp_crypto_broker_internal_copy_transaction_response(
				transaction, response);
		response->replayed = true;
		broker->replayed_requests++;
		(void)k_mutex_unlock(&broker->lock);
		pqcp_runtime_secure_zero(
			request_digest, sizeof(request_digest));
		return ret != 0 ? ret : response->result;
	}
	ret = prepare_transaction(
		broker, request, &authorization,
		request_digest, now_ms, &transaction);
	(void)k_mutex_unlock(&broker->lock);
	if (ret != 0) {
		response->result = ret;
		broker->rejected_requests++;
		pqcp_runtime_secure_zero(
			request_digest, sizeof(request_digest));
		return ret;
	}
	dispatch_result =
		pqcp_crypto_broker_internal_dispatch(
			broker, request, &authorization,
			transaction, response);
	uint64_t completed_at_ms =
		pqcp_runtime_internal_now_ms();

	if (completed_at_ms < now_ms) {
		completed_at_ms = now_ms;
	}
	ret = k_mutex_lock(&broker->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			request_digest, sizeof(request_digest));
		return ret;
	}
	finish_transaction(
		broker, request, &authorization, transaction,
		response, dispatch_result, completed_at_ms);
	ret = pqcp_crypto_broker_internal_create_receipt(
		broker, request, &authorization, transaction,
		response);
	if (ret != 0 && response->result == 0) {
		response->result = ret;
		transaction->result = ret;
		transaction->state =
			PQCP_CRYPTO_BROKER_TRANSACTION_FAILED;
	}
	transaction->receipt = response->receipt;
	(void)k_mutex_unlock(&broker->lock);
	pqcp_runtime_secure_zero(
		request_digest, sizeof(request_digest));
	return response->result;
}

int pqcp_crypto_broker_cancel(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	const uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	uint64_t now_ms)
{
	struct pqcp_crypto_broker_transaction *transaction;
	struct pqcp_crypto_broker_principal *principal;
	int principal_index;
	int transaction_index;
	int ret;

	if (broker == NULL || !broker->initialized ||
	    principal_id == NULL || request_id == NULL ||
	    pqcp_crypto_broker_internal_all_zero(
		    request_id,
		    PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&broker->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	principal_index =
		pqcp_crypto_broker_internal_principal_index(
			broker, principal_id);
	if (principal_index < 0) {
		(void)k_mutex_unlock(&broker->lock);
		return -ENOENT;
	}
	transaction_index =
		pqcp_crypto_broker_internal_transaction_index(
			broker, (uint32_t)principal_index,
			request_id);
	if (transaction_index < 0) {
		(void)k_mutex_unlock(&broker->lock);
		return -ENOENT;
	}
	transaction =
		&broker->storage.transactions[transaction_index];
	principal =
		&broker->storage.principals[principal_index];
	if (terminal_state(transaction->state)) {
		(void)k_mutex_unlock(&broker->lock);
		return -EALREADY;
	}
	if (now_ms < transaction->accepted_at_ms) {
		(void)k_mutex_unlock(&broker->lock);
		return -EINVAL;
	}
	if (transaction->state ==
	    PQCP_CRYPTO_BROKER_TRANSACTION_ACCEPTED) {
		transaction->state =
			PQCP_CRYPTO_BROKER_TRANSACTION_CANCELLED;
		transaction->result = -ECANCELED;
		transaction->completed_at_ms = now_ms;
		pqcp_crypto_broker_internal_complete_quota(
			principal, 0U, true);
		broker->cancelled_requests++;
	} else {
		transaction->state =
			PQCP_CRYPTO_BROKER_TRANSACTION_CANCEL_REQUESTED;
	}
	(void)k_mutex_unlock(&broker->lock);
	return 0;
}

int pqcp_crypto_broker_forget(
	struct pqcp_crypto_broker *broker,
	uint64_t now_ms,
	uint32_t *forgotten_count)
{
	uint32_t forgotten = 0U;
	int ret;

	if (broker == NULL || !broker->initialized ||
	    now_ms == 0U || forgotten_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&broker->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < broker->storage.transaction_capacity;
	     ++index) {
		struct pqcp_crypto_broker_transaction *transaction =
			&broker->storage.transactions[index];

		if (!terminal_state(transaction->state) ||
		    transaction->completed_at_ms == 0U ||
		    now_ms < transaction->completed_at_ms ||
		    now_ms - transaction->completed_at_ms <
			    broker->config.transaction_retention_ms) {
			continue;
		}
		pqcp_runtime_secure_zero(
			transaction, sizeof(*transaction));
		forgotten++;
	}
	(void)k_mutex_unlock(&broker->lock);
	*forgotten_count = forgotten;
	return 0;
}
