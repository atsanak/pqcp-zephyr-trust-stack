/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Stable host ABI dispatcher for the fleet artifact core.
 */

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/fleet_artifact_ffi.h>

#define ARTIFACT_IMPLEMENTATION_VERSION 1U
#define ARTIFACT_CONTEXT_FLAG_LEGACY_V1 (UINT32_C(1) << 0)
#define ARTIFACT_MIN_WORKSPACE 512U
#define ARTIFACT_SIGN1_OVERHEAD 4096U
#define ARTIFACT_EAT_OVERHEAD 6144U

static bool buffer_valid(
	const struct pqcp_fleet_artifact_buffer *buffer)
{
	return buffer != NULL &&
	       (buffer->data != NULL || buffer->capacity == 0U) &&
	       buffer->length <= buffer->capacity;
}

static bool const_buffer_valid(
	const struct pqcp_fleet_artifact_const_buffer *buffer)
{
	return buffer != NULL &&
	       (buffer->data != NULL || buffer->length == 0U);
}

static struct pqcp_fleet_cose_crypto cose_crypto(
	const struct pqcp_fleet_artifact_context *context)
{
	const struct pqcp_fleet_cose_crypto crypto = {
		.context = context->crypto.context,
		.sign = context->crypto.sign,
		.verify = context->crypto.verify,
		.hash = context->crypto.hash,
	};

	return crypto;
}

static void response_reset(
	struct pqcp_fleet_artifact_response *response)
{
	memset(response, 0, sizeof(*response));
	response->abi_version = PQCP_FLEET_ARTIFACT_ABI_VERSION;
	response->kind = PQCP_FLEET_ARTIFACT_NONE;
}

static int response_digest(
	const struct pqcp_fleet_artifact_context *context,
	const uint8_t *data,
	size_t length,
	struct pqcp_fleet_artifact_response *response)
{
	size_t digest_length = 0U;
	int ret;

	if (context->crypto.hash == NULL) {
		return 0;
	}
	ret = context->crypto.hash(
		context->crypto.context, data, length,
		response->digest, sizeof(response->digest),
		&digest_length);
	if (ret != 0) {
		pqcp_fleet_artifact_secure_zero(
			response->digest, sizeof(response->digest));
		return PQCP_FLEET_COSE_ERR_CRYPTO;
	}
	if (digest_length == 0U ||
	    digest_length > sizeof(response->digest)) {
		pqcp_fleet_artifact_secure_zero(
			response->digest, sizeof(response->digest));
		return PQCP_FLEET_COSE_ERR_CRYPTO;
	}
	response->digest_length = digest_length;
	return 0;
}

static int execute_validate(
	struct pqcp_fleet_artifact_request *request,
	struct pqcp_fleet_artifact_response *response)
{
	int ret = pqcp_fleet_cbor_validate(
		request->input.data, request->input.length);

	if (ret == 0) {
		ret = pqcp_fleet_artifact_classify(
			request->input.data, request->input.length,
			&response->kind);
	}
	return ret;
}

static int execute_sign1_sign(
	struct pqcp_fleet_artifact_context *context,
	struct pqcp_fleet_artifact_request *request,
	struct pqcp_fleet_artifact_response *response)
{
	const struct pqcp_fleet_artifact_sign1_options *options =
		request->options;
	const struct pqcp_fleet_cose_crypto crypto =
		cose_crypto(context);
	size_t output_length = 0U;
	int ret;

	if (options == NULL ||
	    options->protected_headers == NULL ||
	    !buffer_valid(&request->output) ||
	    !const_buffer_valid(&request->payload) ||
	    !const_buffer_valid(&request->external_aad)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_cose_sign1_sign(
		options->protected_headers,
		options->unprotected_headers,
		request->payload.data, request->payload.length,
		request->external_aad.data,
		request->external_aad.length,
		&crypto, context->workspace,
		context->workspace_capacity,
		request->output.data, request->output.capacity,
		&output_length);
	if (ret == 0) {
		request->output.length = output_length;
		response->bytes_written = output_length;
		response->kind = PQCP_FLEET_ARTIFACT_COSE_SIGN1;
	}
	return ret;
}

static int execute_sign1_verify(
	struct pqcp_fleet_artifact_context *context,
	struct pqcp_fleet_artifact_request *request,
	struct pqcp_fleet_artifact_response *response)
{
	struct pqcp_fleet_artifact_sign1_verify_options *options =
		(void *)request->options;
	const struct pqcp_fleet_cose_crypto crypto =
		cose_crypto(context);
	struct pqcp_fleet_cose_sign1 local;
	struct pqcp_fleet_cose_sign1 *decoded =
		options != NULL && options->decoded != NULL ?
			options->decoded : &local;
	int ret;

	if (!const_buffer_valid(&request->input) ||
	    !const_buffer_valid(&request->payload) ||
	    !const_buffer_valid(&request->external_aad)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	memset(decoded, 0, sizeof(*decoded));
	ret = pqcp_fleet_cose_sign1_verify(
		request->input.data, request->input.length,
		request->payload.data, request->payload.length,
		request->external_aad.data,
		request->external_aad.length,
		&crypto, context->workspace,
		context->workspace_capacity, decoded);
	if (ret == 0) {
		response->kind = PQCP_FLEET_ARTIFACT_COSE_SIGN1;
	}
	if (decoded == &local) {
		pqcp_fleet_artifact_secure_zero(&local, sizeof(local));
	}
	return ret;
}

static int execute_key_encode(
	struct pqcp_fleet_artifact_request *request,
	struct pqcp_fleet_artifact_response *response)
{
	struct pqcp_fleet_artifact_key_options *options =
		request->object;
	size_t output_length = 0U;
	int ret;

	if (options == NULL || options->key == NULL ||
	    !buffer_valid(&request->output)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_cose_key_encode(
		options->key, options->include_private,
		request->output.data, request->output.capacity,
		&output_length);
	if (ret == 0) {
		request->output.length = output_length;
		response->bytes_written = output_length;
		response->kind = PQCP_FLEET_ARTIFACT_COSE_KEY;
	}
	return ret;
}

static int execute_key_decode(
	struct pqcp_fleet_artifact_request *request,
	struct pqcp_fleet_artifact_response *response)
{
	struct pqcp_fleet_artifact_key_options *options =
		request->object;
	int ret;

	if (options == NULL || options->key == NULL ||
	    !const_buffer_valid(&request->input)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_cose_key_decode(
		request->input.data, request->input.length,
		options->allow_private, options->key);
	if (ret == 0) {
		response->kind = PQCP_FLEET_ARTIFACT_COSE_KEY;
	}
	return ret;
}

static int execute_eat_sign(
	struct pqcp_fleet_artifact_context *context,
	struct pqcp_fleet_artifact_request *request,
	struct pqcp_fleet_artifact_response *response)
{
	const struct pqcp_fleet_eat_claims *claims =
		request->object;
	const struct pqcp_fleet_cose_crypto crypto =
		cose_crypto(context);
	size_t output_length = 0U;
	int ret;

	if (claims == NULL ||
	    !const_buffer_valid(&request->key_id) ||
	    !buffer_valid(&request->output)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_eat_token_sign(
		claims, request->key_id.data,
		request->key_id.length, &crypto,
		context->workspace, context->workspace_capacity,
		request->output.data, request->output.capacity,
		&output_length);
	if (ret == 0) {
		request->output.length = output_length;
		response->bytes_written = output_length;
		response->kind =
			claims->role ==
				PQCP_FLEET_EAT_ROLE_ATTESTATION_RESULT ?
				PQCP_FLEET_ARTIFACT_EAT_RESULT :
				PQCP_FLEET_ARTIFACT_EAT_EVIDENCE;
	}
	return ret;
}

static int execute_eat_verify(
	struct pqcp_fleet_artifact_context *context,
	struct pqcp_fleet_artifact_request *request,
	struct pqcp_fleet_artifact_response *response)
{
	struct pqcp_fleet_artifact_eat_verify_options *options =
		request->object;
	const struct pqcp_fleet_cose_crypto crypto =
		cose_crypto(context);
	int ret;

	if (options == NULL || options->claims == NULL ||
	    !const_buffer_valid(&request->input)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_eat_token_verify(
		request->input.data, request->input.length,
		&crypto, options->freshness,
		context->workspace, context->workspace_capacity,
		options->claims);
	if (ret == 0) {
		response->kind =
			options->claims->role ==
				PQCP_FLEET_EAT_ROLE_ATTESTATION_RESULT ?
				PQCP_FLEET_ARTIFACT_EAT_RESULT :
				PQCP_FLEET_ARTIFACT_EAT_EVIDENCE;
	}
	return ret;
}

static int execute_eat_appraise(
	struct pqcp_fleet_artifact_request *request,
	struct pqcp_fleet_artifact_response *response)
{
	struct pqcp_fleet_artifact_eat_appraise_options *options =
		request->object;
	int ret;

	if (options == NULL || options->claims == NULL ||
	    options->policy == NULL || options->result == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (options->claims->role ==
	    PQCP_FLEET_EAT_ROLE_ATTESTATION_RESULT) {
		ret = pqcp_fleet_eat_result_authorize(
			options->claims, options->policy,
			options->result);
		response->kind = PQCP_FLEET_ARTIFACT_EAT_RESULT;
	} else {
		ret = pqcp_fleet_eat_appraise_evidence(
			options->claims, options->policy,
			options->result);
		response->kind = PQCP_FLEET_ARTIFACT_EAT_EVIDENCE;
	}
	return ret;
}

static int validate_request(
	const struct pqcp_fleet_artifact_context *context,
	const struct pqcp_fleet_artifact_request *request,
	const struct pqcp_fleet_artifact_response *response)
{
	if (context == NULL || request == NULL || response == NULL ||
	    context->abi_version !=
		    PQCP_FLEET_ARTIFACT_ABI_VERSION ||
	    request->abi_version !=
		    PQCP_FLEET_ARTIFACT_ABI_VERSION ||
	    context->workspace == NULL ||
	    context->workspace_capacity <
		    ARTIFACT_MIN_WORKSPACE ||
	    request->operation <=
		    PQCP_FLEET_ARTIFACT_OP_NONE ||
	    request->operation >
		    PQCP_FLEET_ARTIFACT_OP_EAT_RESULT_SIGN) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	return 0;
}

int pqcp_fleet_artifact_version(
	struct pqcp_fleet_artifact_version *version)
{
	if (version == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	version->abi_version = PQCP_FLEET_ARTIFACT_ABI_VERSION;
	version->implementation_version =
		ARTIFACT_IMPLEMENTATION_VERSION;
	version->features =
		PQCP_FLEET_ARTIFACT_FEATURE_COSE_SIGN1 |
		PQCP_FLEET_ARTIFACT_FEATURE_COSE_AKP |
		PQCP_FLEET_ARTIFACT_FEATURE_EAT_CWT |
		PQCP_FLEET_ARTIFACT_FEATURE_RATS |
		PQCP_FLEET_ARTIFACT_FEATURE_LEGACY_V1;
	return 0;
}

size_t pqcp_fleet_artifact_context_size(void)
{
	return sizeof(struct pqcp_fleet_artifact_context);
}

size_t pqcp_fleet_artifact_required_workspace(
	enum pqcp_fleet_artifact_operation operation,
	size_t payload_length)
{
	size_t overhead;

	switch (operation) {
	case PQCP_FLEET_ARTIFACT_OP_SIGN1_SIGN:
	case PQCP_FLEET_ARTIFACT_OP_SIGN1_VERIFY:
	case PQCP_FLEET_ARTIFACT_OP_KEY_ENCODE:
	case PQCP_FLEET_ARTIFACT_OP_KEY_DECODE:
		overhead = ARTIFACT_SIGN1_OVERHEAD;
		break;
	case PQCP_FLEET_ARTIFACT_OP_EAT_SIGN:
	case PQCP_FLEET_ARTIFACT_OP_EAT_VERIFY:
	case PQCP_FLEET_ARTIFACT_OP_EAT_APPRAISE:
	case PQCP_FLEET_ARTIFACT_OP_EAT_RESULT_SIGN:
		overhead = ARTIFACT_EAT_OVERHEAD;
		break;
	case PQCP_FLEET_ARTIFACT_OP_VALIDATE_CBOR:
		overhead = ARTIFACT_MIN_WORKSPACE;
		break;
	default:
		return 0U;
	}
	if (payload_length > SIZE_MAX - overhead) {
		return 0U;
	}
	return payload_length + overhead;
}

int pqcp_fleet_artifact_context_init(
	struct pqcp_fleet_artifact_context *context,
	const struct pqcp_fleet_artifact_crypto_vtable *crypto,
	uint8_t *workspace,
	size_t workspace_capacity,
	uint32_t flags)
{
	if (context == NULL || crypto == NULL ||
	    crypto->abi_version !=
		    PQCP_FLEET_ARTIFACT_ABI_VERSION ||
	    workspace == NULL ||
	    workspace_capacity < ARTIFACT_MIN_WORKSPACE ||
	    (flags & ~ARTIFACT_CONTEXT_FLAG_LEGACY_V1) != 0U) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	memset(context, 0, sizeof(*context));
	context->abi_version = PQCP_FLEET_ARTIFACT_ABI_VERSION;
	context->flags = flags;
	context->crypto = *crypto;
	context->workspace = workspace;
	context->workspace_capacity = workspace_capacity;
	return 0;
}

int pqcp_fleet_artifact_execute(
	struct pqcp_fleet_artifact_context *context,
	struct pqcp_fleet_artifact_request *request,
	struct pqcp_fleet_artifact_response *response)
{
	int ret;

	if (response != NULL) {
		response_reset(response);
	}
	ret = validate_request(context, request, response);
	if (ret != 0) {
		if (context != NULL) {
			context->last_error = ret;
		}
		if (response != NULL) {
			response->result = ret;
		}
		return ret;
	}
	switch (request->operation) {
	case PQCP_FLEET_ARTIFACT_OP_VALIDATE_CBOR:
		ret = execute_validate(request, response);
		break;
	case PQCP_FLEET_ARTIFACT_OP_SIGN1_SIGN:
		ret = execute_sign1_sign(context, request, response);
		break;
	case PQCP_FLEET_ARTIFACT_OP_SIGN1_VERIFY:
		ret = execute_sign1_verify(context, request, response);
		break;
	case PQCP_FLEET_ARTIFACT_OP_KEY_ENCODE:
		ret = execute_key_encode(request, response);
		break;
	case PQCP_FLEET_ARTIFACT_OP_KEY_DECODE:
		ret = execute_key_decode(request, response);
		break;
	case PQCP_FLEET_ARTIFACT_OP_EAT_SIGN:
	case PQCP_FLEET_ARTIFACT_OP_EAT_RESULT_SIGN:
		ret = execute_eat_sign(context, request, response);
		break;
	case PQCP_FLEET_ARTIFACT_OP_EAT_VERIFY:
		ret = execute_eat_verify(context, request, response);
		break;
	case PQCP_FLEET_ARTIFACT_OP_EAT_APPRAISE:
		ret = execute_eat_appraise(request, response);
		break;
	default:
		ret = PQCP_FLEET_COSE_ERR_UNSUPPORTED;
		break;
	}
	if (ret == 0) {
		const uint8_t *digest_data = NULL;
		size_t digest_length = 0U;

		if (response->bytes_written != 0U) {
			digest_data = request->output.data;
			digest_length = response->bytes_written;
		} else if (request->input.length != 0U) {
			digest_data = request->input.data;
			digest_length = request->input.length;
		}
		if (digest_data != NULL) {
			ret = response_digest(
				context, digest_data,
				digest_length, response);
		}
	}
	context->operation_count++;
	context->last_error = ret;
	response->result = ret;
	if (ret != 0 && request->output.data != NULL) {
		pqcp_fleet_artifact_secure_zero(
			request->output.data,
			request->output.capacity);
		request->output.length = 0U;
		response->bytes_written = 0U;
	}
	return ret;
}

int pqcp_fleet_artifact_classify(
	const uint8_t *encoded,
	size_t encoded_length,
	enum pqcp_fleet_artifact_kind *kind)
{
	struct pqcp_fleet_cbor_reader reader;
	struct pqcp_fleet_cbor_head head;
	size_t saved;
	int ret;

	if (encoded == NULL || encoded_length == 0U ||
	    kind == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	*kind = PQCP_FLEET_ARTIFACT_NONE;
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	saved = reader.offset;
	ret = pqcp_fleet_cbor_read_head(&reader, &head);
	if (ret != 0) {
		return ret;
	}
	if (head.major == PQCP_FLEET_CBOR_TAG &&
	    head.argument == PQCP_FLEET_COSE_SIGN1_TAG) {
		*kind = PQCP_FLEET_ARTIFACT_COSE_SIGN1;
		return 0;
	}
	if (head.major == PQCP_FLEET_CBOR_TAG &&
	    head.argument == PQCP_FLEET_COSE_KEY_TAG) {
		*kind = PQCP_FLEET_ARTIFACT_COSE_KEY;
		return 0;
	}
	reader.offset = saved;
	if (head.major == PQCP_FLEET_CBOR_ARRAY &&
	    head.argument == 4U) {
		*kind = PQCP_FLEET_ARTIFACT_COSE_SIGN1;
		return 0;
	}
	if (head.major == PQCP_FLEET_CBOR_MAP) {
		*kind = PQCP_FLEET_ARTIFACT_COSE_KEY;
		return 0;
	}
	return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
}

int pqcp_fleet_artifact_last_error(
	const struct pqcp_fleet_artifact_context *context)
{
	return context != NULL &&
	       context->abi_version ==
		       PQCP_FLEET_ARTIFACT_ABI_VERSION ?
		       context->last_error :
		       PQCP_FLEET_COSE_ERR_ARGUMENT;
}

const char *pqcp_fleet_cose_error_string(int error)
{
	switch (error) {
	case PQCP_FLEET_COSE_OK:
		return "ok";
	case PQCP_FLEET_COSE_ERR_ARGUMENT:
		return "invalid-argument";
	case PQCP_FLEET_COSE_ERR_CAPACITY:
		return "insufficient-capacity";
	case PQCP_FLEET_COSE_ERR_ENCODING:
		return "invalid-encoding";
	case PQCP_FLEET_COSE_ERR_NON_CANONICAL:
		return "non-canonical";
	case PQCP_FLEET_COSE_ERR_UNSUPPORTED:
		return "unsupported";
	case PQCP_FLEET_COSE_ERR_CRYPTO:
		return "crypto-failure";
	case PQCP_FLEET_COSE_ERR_SIGNATURE:
		return "signature-rejected";
	case PQCP_FLEET_COSE_ERR_KEY:
		return "invalid-key";
	case PQCP_FLEET_COSE_ERR_DUPLICATE:
		return "duplicate-map-key";
	case PQCP_FLEET_COSE_ERR_REQUIRED:
		return "required-field-missing";
	case PQCP_FLEET_COSE_ERR_TRAILING:
		return "trailing-data";
	case PQCP_FLEET_COSE_ERR_POLICY:
		return "policy-rejected";
	default:
		return "unknown-error";
	}
}

const char *pqcp_fleet_artifact_error_string(int error)
{
	return pqcp_fleet_cose_error_string(error);
}

void pqcp_fleet_artifact_secure_zero(
	void *memory,
	size_t length)
{
	volatile uint8_t *bytes = memory;

	if (memory == NULL) {
		return;
	}
	while (length != 0U) {
		*bytes++ = 0U;
		length--;
	}
}
