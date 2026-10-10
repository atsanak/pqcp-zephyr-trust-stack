/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Crypto broker request normalization, policy evaluation, and quota control.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/crypto_broker.h>
#include <pqcp_zephyr/errno.h>

#include "crypto_broker_internal.h"
#include "runtime_internal.h"

#define BROKER_REQUEST_DIGEST_BYTES 320U

static bool operation_valid(
	enum pqcp_crypto_broker_operation operation)
{
	return operation > PQCP_CRYPTO_BROKER_OPERATION_NONE &&
	       operation < PQCP_CRYPTO_BROKER_OPERATION_COUNT;
}

static uint32_t valid_request_flags(void)
{
	return PQCP_CRYPTO_BROKER_REQUEST_CHANNEL_AUTHENTICATED |
	       PQCP_CRYPTO_BROKER_REQUEST_ZERO_OUTPUT_ON_FAILURE |
	       PQCP_CRYPTO_BROKER_REQUEST_REQUIRE_SIGNED_RECEIPT;
}

static bool handle_required(
	enum pqcp_crypto_broker_operation operation)
{
	switch (operation) {
	case PQCP_CRYPTO_BROKER_OPERATION_EXPORT_PUBLIC:
	case PQCP_CRYPTO_BROKER_OPERATION_SIGN:
	case PQCP_CRYPTO_BROKER_OPERATION_VERIFY:
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_ENCAPSULATE:
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_DECAPSULATE:
	case PQCP_CRYPTO_BROKER_OPERATION_HKDF_DERIVE:
	case PQCP_CRYPTO_BROKER_OPERATION_MAC:
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_ENCRYPT:
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_DECRYPT:
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_ROTATE:
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_DESTROY:
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_METADATA:
		return true;
	default:
		return false;
	}
}

static bool key_spec_required(
	enum pqcp_crypto_broker_operation operation)
{
	return operation ==
		       PQCP_CRYPTO_BROKER_OPERATION_KEY_GENERATE ||
	       operation ==
		       PQCP_CRYPTO_BROKER_OPERATION_HKDF_DERIVE ||
	       operation ==
		       PQCP_CRYPTO_BROKER_OPERATION_KEY_ROTATE;
}

static bool operation_creates_key(
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

static uint32_t required_usage(
	enum pqcp_crypto_broker_operation operation)
{
	switch (operation) {
	case PQCP_CRYPTO_BROKER_OPERATION_EXPORT_PUBLIC:
		return PQCP_RUNTIME_USAGE_EXPORT_PUBLIC;
	case PQCP_CRYPTO_BROKER_OPERATION_SIGN:
		return PQCP_RUNTIME_USAGE_SIGN;
	case PQCP_CRYPTO_BROKER_OPERATION_VERIFY:
		return PQCP_RUNTIME_USAGE_VERIFY;
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_ENCAPSULATE:
		return PQCP_RUNTIME_USAGE_ENCAPSULATE;
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_DECAPSULATE:
		return PQCP_RUNTIME_USAGE_DECAPSULATE;
	case PQCP_CRYPTO_BROKER_OPERATION_HKDF_DERIVE:
		return PQCP_RUNTIME_USAGE_DERIVE;
	case PQCP_CRYPTO_BROKER_OPERATION_MAC:
		return PQCP_RUNTIME_USAGE_MAC;
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_ENCRYPT:
		return PQCP_RUNTIME_USAGE_ENCRYPT;
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_DECRYPT:
		return PQCP_RUNTIME_USAGE_DECRYPT;
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_ROTATE:
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_DESTROY:
		return PQCP_RUNTIME_USAGE_DESTROY;
	default:
		return 0U;
	}
}

static enum pqcp_runtime_key_family request_family(
	const struct pqcp_crypto_broker_request *request)
{
	if (request->operation ==
	    PQCP_CRYPTO_BROKER_OPERATION_KEY_GENERATE) {
		return request->key_spec.family;
	}
	if (pqcp_runtime_key_handle_is_valid(
		    &request->primary_key)) {
		return request->primary_key.family;
	}
	return request->key_spec.family;
}

static int validate_key_spec(
	const struct pqcp_crypto_broker_key_spec *spec,
	uint64_t submitted_at_ms)
{
	if (spec == NULL ||
	    !pqcp_runtime_internal_key_family_valid(spec->family) ||
	    !pqcp_runtime_internal_level_valid(
		    spec->family, spec->level) ||
	    !pqcp_runtime_internal_usage_valid(spec->usage) ||
	    spec->expires_at_ms <= submitted_at_ms ||
	    !pqcp_runtime_internal_text_valid(
		    spec->label, sizeof(spec->label))) {
		return -EINVAL;
	}
	switch (spec->family) {
	case PQCP_RUNTIME_KEY_MLKEM_KEYPAIR:
		if ((spec->usage &
		     (PQCP_RUNTIME_USAGE_ENCAPSULATE |
		      PQCP_RUNTIME_USAGE_DECAPSULATE)) == 0U) {
			return -EINVAL;
		}
		break;
	case PQCP_RUNTIME_KEY_MLKEM_PUBLIC:
		if ((spec->usage &
		     PQCP_RUNTIME_USAGE_ENCAPSULATE) == 0U ||
		    spec->persistent) {
			return -EINVAL;
		}
		break;
	case PQCP_RUNTIME_KEY_MLDSA_KEYPAIR:
		if ((spec->usage &
		     PQCP_RUNTIME_USAGE_SIGN) == 0U) {
			return -EINVAL;
		}
		break;
	case PQCP_RUNTIME_KEY_MLDSA_PUBLIC:
		if ((spec->usage &
		     PQCP_RUNTIME_USAGE_VERIFY) == 0U ||
		    spec->persistent) {
			return -EINVAL;
		}
		break;
	case PQCP_RUNTIME_KEY_SHARED_SECRET:
		if ((spec->usage &
		     PQCP_RUNTIME_USAGE_DERIVE) == 0U ||
		    spec->persistent ||
		    spec->exportable_public) {
			return -EINVAL;
		}
		break;
	case PQCP_RUNTIME_KEY_AEAD:
		if ((spec->usage &
		     (PQCP_RUNTIME_USAGE_ENCRYPT |
		      PQCP_RUNTIME_USAGE_DECRYPT |
		      PQCP_RUNTIME_USAGE_MAC)) == 0U ||
		    spec->exportable_public) {
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int validate_operation_buffers(
	const struct pqcp_crypto_broker_request *request)
{
	switch (request->operation) {
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_GENERATE:
	case PQCP_CRYPTO_BROKER_OPERATION_EXPORT_PUBLIC:
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_DESTROY:
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_METADATA:
		if (request->input_length != 0U ||
		    request->aux_input_length != 0U ||
		    request->context_length != 0U) {
			return -EINVAL;
		}
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_SIGN:
		if (request->input == NULL ||
		    request->input_length == 0U) {
			return -EINVAL;
		}
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_VERIFY:
		if (request->input == NULL ||
		    request->input_length == 0U ||
		    request->aux_input == NULL ||
		    request->aux_input_length == 0U) {
			return -EINVAL;
		}
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_ENCAPSULATE:
		if (request->input_length != 0U ||
		    request->aux_input_length != 0U) {
			return -EINVAL;
		}
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_DECAPSULATE:
		if (request->input == NULL ||
		    request->input_length == 0U) {
			return -EINVAL;
		}
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_HKDF_DERIVE:
		if (request->input == NULL ||
		    request->input_length == 0U ||
		    request->aux_input == NULL ||
		    request->aux_input_length == 0U) {
			return -EINVAL;
		}
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_MAC:
		if (request->input == NULL ||
		    request->input_length == 0U ||
		    request->aux_input_length != 0U) {
			return -EINVAL;
		}
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_ENCRYPT:
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_DECRYPT:
		if (request->input == NULL ||
		    request->input_length == 0U ||
		    request->aux_input == NULL ||
		    request->aux_input_length !=
			    PQCP_RUNTIME_AEAD_NONCE_BYTES) {
			return -EINVAL;
		}
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_ROTATE:
		if (request->input_length != 0U ||
		    request->aux_input_length != 0U) {
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int pqcp_crypto_broker_internal_validate_request(
	const struct pqcp_crypto_broker_request *request)
{
	if (request == NULL ||
	    request->schema_version !=
		    PQCP_CRYPTO_BROKER_SCHEMA_VERSION ||
	    pqcp_crypto_broker_internal_all_zero(
		    request->request_id,
		    sizeof(request->request_id)) ||
	    pqcp_crypto_broker_internal_all_zero(
		    request->capability,
		    sizeof(request->capability)) ||
	    !pqcp_runtime_internal_text_valid(
		    request->principal_id,
		    sizeof(request->principal_id)) ||
	    !operation_valid(request->operation) ||
	    request->submitted_at_ms == 0U ||
	    request->deadline_ms <= request->submitted_at_ms ||
	    (request->flags & ~valid_request_flags()) != 0U ||
	    (request->input == NULL &&
	     request->input_length != 0U) ||
	    (request->aux_input == NULL &&
	     request->aux_input_length != 0U) ||
	    (request->context == NULL &&
	     request->context_length != 0U) ||
	    request->input_length >
		    PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    request->aux_input_length >
		    PQCP_RUNTIME_MAX_INPUT_BYTES ||
	    request->context_length >
		    PQCP_RUNTIME_MAX_CONTEXT_BYTES) {
		return -EINVAL;
	}
	if (handle_required(request->operation) &&
	    !pqcp_runtime_key_handle_is_valid(
		    &request->primary_key)) {
		return -EINVAL;
	}
	if (!handle_required(request->operation) &&
	    pqcp_runtime_key_handle_is_valid(
		    &request->primary_key)) {
		return -EINVAL;
	}
	if (key_spec_required(request->operation) &&
	    validate_key_spec(
		    &request->key_spec,
		    request->submitted_at_ms) != 0) {
		return -EINVAL;
	}
	if (!key_spec_required(request->operation) &&
	    request->key_spec.family !=
		    PQCP_RUNTIME_KEY_NONE) {
		return -EINVAL;
	}
	return validate_operation_buffers(request);
}

static size_t append_u32(
	uint8_t *output,
	size_t offset,
	uint32_t value)
{
	pqcp_runtime_internal_write_u32(output + offset, value);
	return offset + 4U;
}

static size_t append_u64(
	uint8_t *output,
	size_t offset,
	uint64_t value)
{
	pqcp_runtime_internal_write_u64(output + offset, value);
	return offset + 8U;
}

static size_t append_handle(
	uint8_t *output,
	size_t offset,
	const struct pqcp_runtime_key_handle *handle)
{
	offset = append_u32(output, offset, handle->slot);
	offset = append_u32(output, offset, handle->generation);
	offset = append_u32(
		output, offset, (uint32_t)handle->backend);
	offset = append_u32(
		output, offset, (uint32_t)handle->family);
	offset = append_u32(output, offset, handle->level);
	return offset;
}

int pqcp_crypto_broker_internal_request_digest(
	const struct pqcp_crypto_broker_request *request,
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES])
{
	uint8_t input_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t aux_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t context_digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint8_t encoded[BROKER_REQUEST_DIGEST_BYTES];
	size_t principal_length;
	size_t label_length;
	size_t offset = 0U;
	int ret;

	if (digest == NULL ||
	    pqcp_crypto_broker_internal_validate_request(
		    request) != 0) {
		return -EINVAL;
	}
	ret = pqcp_runtime_internal_sha256(
		request->input, request->input_length,
		input_digest);
	if (ret == 0) {
		ret = pqcp_runtime_internal_sha256(
			request->aux_input,
			request->aux_input_length, aux_digest);
	}
	if (ret == 0) {
		ret = pqcp_runtime_internal_sha256(
			request->context,
			request->context_length,
			context_digest);
	}
	if (ret != 0) {
		goto cleanup;
	}
	memset(encoded, 0, sizeof(encoded));
	memcpy(encoded + offset, "PQCP-BROKER-REQUEST-V1", 22U);
	offset += 22U;
	memcpy(encoded + offset, request->request_id,
	       sizeof(request->request_id));
	offset += sizeof(request->request_id);
	memcpy(encoded + offset, request->capability,
	       sizeof(request->capability));
	offset += sizeof(request->capability);
	principal_length = strnlen(
		request->principal_id,
		sizeof(request->principal_id));
	encoded[offset++] = (uint8_t)principal_length;
	memcpy(encoded + offset, request->principal_id,
	       principal_length);
	offset += principal_length;
	offset = append_u32(
		encoded, offset, (uint32_t)request->operation);
	offset = append_u64(
		encoded, offset, request->submitted_at_ms);
	offset = append_u64(
		encoded, offset, request->deadline_ms);
	offset = append_u32(encoded, offset, request->flags);
	offset = append_u32(encoded, offset, request->level);
	offset = append_u32(
		encoded, offset,
		(uint32_t)request->key_spec.family);
	offset = append_u32(
		encoded, offset, request->key_spec.level);
	offset = append_u32(
		encoded, offset, request->key_spec.usage);
	offset = append_u64(
		encoded, offset,
		request->key_spec.expires_at_ms);
	encoded[offset++] =
		request->key_spec.persistent ? 1U : 0U;
	encoded[offset++] =
		request->key_spec.exportable_public ? 1U : 0U;
	label_length = strnlen(
		request->key_spec.label,
		sizeof(request->key_spec.label));
	encoded[offset++] = (uint8_t)label_length;
	memcpy(encoded + offset, request->key_spec.label,
	       label_length);
	offset += label_length;
	offset = append_handle(
		encoded, offset, &request->primary_key);
	offset = append_handle(
		encoded, offset, &request->secondary_key);
	offset = append_u64(
		encoded, offset, request->input_length);
	offset = append_u64(
		encoded, offset, request->aux_input_length);
	offset = append_u64(
		encoded, offset, request->context_length);
	memcpy(encoded + offset, input_digest,
	       sizeof(input_digest));
	offset += sizeof(input_digest);
	memcpy(encoded + offset, aux_digest,
	       sizeof(aux_digest));
	offset += sizeof(aux_digest);
	memcpy(encoded + offset, context_digest,
	       sizeof(context_digest));
	offset += sizeof(context_digest);
	if (offset > sizeof(encoded)) {
		ret = -EOVERFLOW;
		goto cleanup;
	}
	ret = pqcp_runtime_internal_sha256(
		encoded, offset, digest);

cleanup:
	pqcp_runtime_secure_zero(
		input_digest, sizeof(input_digest));
	pqcp_runtime_secure_zero(
		aux_digest, sizeof(aux_digest));
	pqcp_runtime_secure_zero(
		context_digest, sizeof(context_digest));
	pqcp_runtime_secure_zero(encoded, sizeof(encoded));
	return ret;
}

uint64_t pqcp_crypto_broker_internal_cost(
	const struct pqcp_crypto_broker_request *request)
{
	uint64_t base;
	uint64_t size_cost;
	uint64_t level_cost;

	if (request == NULL ||
	    !operation_valid(request->operation)) {
		return UINT64_MAX;
	}
	switch (request->operation) {
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_GENERATE:
		base = 500U;
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_SIGN:
		base = 300U;
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_VERIFY:
		base = 220U;
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_ENCAPSULATE:
		base = 260U;
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_KEM_DECAPSULATE:
		base = 320U;
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_HKDF_DERIVE:
		base = 80U;
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_ENCRYPT:
	case PQCP_CRYPTO_BROKER_OPERATION_AEAD_DECRYPT:
		base = 40U;
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_MAC:
		base = 30U;
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_ROTATE:
		base = 600U;
		break;
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_DESTROY:
	case PQCP_CRYPTO_BROKER_OPERATION_KEY_METADATA:
	case PQCP_CRYPTO_BROKER_OPERATION_EXPORT_PUBLIC:
		base = 10U;
		break;
	default:
		base = 100U;
		break;
	}
	size_cost =
		(request->input_length +
		 request->aux_input_length +
		 request->context_length + 255U) / 256U;
	level_cost = request->level != 0U ?
		request->level / 32U :
		request_family(request) ==
			PQCP_RUNTIME_KEY_AEAD ? 8U : 1U;
	if (UINT64_MAX - base < size_cost ||
	    UINT64_MAX - base - size_cost < level_cost) {
		return UINT64_MAX;
	}
	return base + size_cost + level_cost;
}

void pqcp_crypto_broker_internal_refresh_window(
	struct pqcp_crypto_broker_principal *principal,
	uint64_t now_ms)
{
	if (principal == NULL || now_ms == 0U) {
		return;
	}
	if (principal->usage.window_started_ms == 0U ||
	    now_ms < principal->usage.window_started_ms ||
	    now_ms - principal->usage.window_started_ms >=
		    principal->quota.window_ms) {
		principal->usage.window_started_ms = now_ms;
		principal->usage.operations = 0U;
		principal->usage.input_bytes = 0U;
		principal->usage.output_bytes = 0U;
		principal->usage.cost_units = 0U;
	}
}

int pqcp_crypto_broker_internal_reserve_quota(
	struct pqcp_crypto_broker_principal *principal,
	const struct pqcp_crypto_broker_request *request,
	uint64_t cost_units,
	uint64_t now_ms)
{
	uint64_t input_bytes;

	if (principal == NULL || request == NULL ||
	    cost_units == UINT64_MAX || now_ms == 0U) {
		return -EINVAL;
	}
	pqcp_crypto_broker_internal_refresh_window(
		principal, now_ms);
	input_bytes = request->input_length +
		      request->aux_input_length +
		      request->context_length;
	if (principal->usage.inflight_requests >=
		    principal->quota.maximum_inflight_requests ||
	    principal->usage.operations >=
		    principal->quota.maximum_operations_per_window ||
	    input_bytes >
		    principal->quota.maximum_input_bytes_per_window -
			    principal->usage.input_bytes ||
	    cost_units >
		    principal->quota.maximum_cost_units_per_window -
			    principal->usage.cost_units ||
	    (operation_creates_key(request->operation) &&
	     principal->usage.active_keys >=
		     principal->quota.maximum_active_keys)) {
		principal->usage.rejected_requests++;
		return -EDQUOT;
	}
	principal->usage.inflight_requests++;
	principal->usage.operations++;
	principal->usage.input_bytes += input_bytes;
	principal->usage.cost_units += cost_units;
	principal->usage.accepted_requests++;
	return 0;
}

void pqcp_crypto_broker_internal_complete_quota(
	struct pqcp_crypto_broker_principal *principal,
	size_t output_length,
	bool cancelled)
{
	if (principal == NULL) {
		return;
	}
	if (principal->usage.inflight_requests != 0U) {
		principal->usage.inflight_requests--;
	}
	principal->usage.output_bytes += output_length;
	if (cancelled) {
		principal->usage.cancelled_requests++;
	} else {
		principal->usage.completed_requests++;
	}
}

static int deny(
	struct pqcp_crypto_broker_authorization *authorization,
	enum pqcp_crypto_broker_decision decision,
	const char *reason,
	int error)
{
	authorization->decision = decision;
	(void)pqcp_runtime_internal_copy_text(
		authorization->reason,
		sizeof(authorization->reason), reason);
	return error;
}

static int validate_capability(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	uint64_t now_ms,
	int principal_index,
	int *grant_index,
	int *capability_index,
	struct pqcp_crypto_broker_authorization *authorization)
{
	struct pqcp_crypto_broker_capability *capability;
	struct pqcp_crypto_broker_grant *grant;

	*capability_index =
		pqcp_crypto_broker_internal_capability_index(
			broker, request->capability);
	if (*capability_index < 0) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_CAPABILITY,
			"unknown capability", -EACCES);
	}
	capability =
		&broker->storage.capabilities[*capability_index];
	if (capability->principal_index !=
	    (uint32_t)principal_index) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_CAPABILITY,
			"capability principal mismatch", -EACCES);
	}
	if (capability->state !=
	    PQCP_CRYPTO_BROKER_CAPABILITY_ACTIVE) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_CAPABILITY,
			"capability inactive", -EKEYREVOKED);
	}
	if (now_ms >= capability->expires_at_ms) {
		capability->state =
			PQCP_CRYPTO_BROKER_CAPABILITY_EXPIRED;
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_CAPABILITY,
			"capability expired", -ETIMEDOUT);
	}
	if (capability->use_count >=
	    capability->maximum_uses) {
		capability->state =
			PQCP_CRYPTO_BROKER_CAPABILITY_EXHAUSTED;
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_CAPABILITY,
			"capability exhausted", -EDQUOT);
	}
	if ((capability->operation_mask &
	     PQCP_CRYPTO_BROKER_OPERATION_BIT(
		     request->operation)) == 0U ||
	    (capability->key_family_mask &
	     PQCP_CRYPTO_BROKER_FAMILY_BIT(
		     request_family(request))) == 0U ||
	    (required_usage(request->operation) &
	     ~capability->key_usage_mask) != 0U) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_CAPABILITY,
			"capability scope mismatch", -EACCES);
	}
	*grant_index = (int)capability->grant_index;
	if (*grant_index < 0 ||
	    (size_t)*grant_index >=
		    broker->storage.grant_capacity) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_GRANT,
			"capability grant missing", -EACCES);
	}
	grant = &broker->storage.grants[*grant_index];
	if (grant->state !=
		    PQCP_CRYPTO_BROKER_GRANT_ACTIVE ||
	    grant->principal_index !=
		    (uint32_t)principal_index) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_GRANT,
			"grant inactive", -EKEYREVOKED);
	}
	if (now_ms < grant->not_before_ms ||
	    now_ms >= grant->expires_at_ms) {
		grant->state =
			PQCP_CRYPTO_BROKER_GRANT_EXPIRED;
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_GRANT,
			"grant outside validity window",
			-ETIMEDOUT);
	}
	if (grant->use_count >= grant->maximum_uses) {
		grant->state =
			PQCP_CRYPTO_BROKER_GRANT_EXHAUSTED;
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_GRANT,
			"grant exhausted", -EDQUOT);
	}
	return 0;
}

static int validate_policy_scope(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	uint64_t now_ms,
	const struct pqcp_crypto_broker_principal *principal,
	const struct pqcp_crypto_broker_grant *grant,
	struct pqcp_crypto_broker_authorization *authorization)
{
	const struct pqcp_crypto_broker_grant_policy *policy =
		&grant->policy;
	uint64_t cost =
		pqcp_crypto_broker_internal_cost(request);
	bool channel_authenticated =
		(request->flags &
		 PQCP_CRYPTO_BROKER_REQUEST_CHANNEL_AUTHENTICATED) != 0U;

	if ((policy->operation_mask &
	     PQCP_CRYPTO_BROKER_OPERATION_BIT(
		     request->operation)) == 0U ||
	    (policy->key_family_mask &
	     PQCP_CRYPTO_BROKER_FAMILY_BIT(
		     request_family(request))) == 0U ||
	    (required_usage(request->operation) &
	     ~policy->key_usage_mask) != 0U) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY,
			"grant scope mismatch", -EACCES);
	}
	if (request->input_length >
		    policy->maximum_input_bytes ||
	    request->aux_input_length >
		    policy->maximum_input_bytes ||
	    request->deadline_ms - now_ms >
		    policy->maximum_deadline_horizon_ms ||
	    cost > policy->cost_unit_limit ||
	    cost > broker->config.maximum_cost_per_request) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY,
			"request exceeds grant limits", -E2BIG);
	}
	if ((broker->config.require_channel_identity ||
	     principal->channel_identity_required ||
	     policy->require_channel_identity) &&
	    !channel_authenticated) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_AUTHENTICATION,
			"channel identity required", -EACCES);
	}
	if (key_spec_required(request->operation)) {
		if (request->key_spec.persistent &&
		    !policy->allow_persistent_keys) {
			return deny(
				authorization,
				PQCP_CRYPTO_BROKER_DECISION_DENY_CUSTODY,
				"persistent custody denied", -EACCES);
		}
		if (request->key_spec.exportable_public &&
		    !policy->allow_public_export) {
			return deny(
				authorization,
				PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY,
				"public export denied", -EACCES);
		}
		if (request->key_spec.expires_at_ms -
			    request->submitted_at_ms >
		    policy->maximum_key_lifetime_ms) {
			return deny(
				authorization,
				PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY,
				"key lifetime exceeds grant", -EACCES);
		}
	}
	authorization->cost_units = cost;
	return 0;
}

static int validate_existing_key(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	const struct pqcp_crypto_broker_principal *principal,
	const struct pqcp_crypto_broker_grant *grant,
	struct pqcp_crypto_broker_authorization *authorization)
{
	struct pqcp_runtime_key_metadata metadata;
	int ret;

	if (!handle_required(request->operation)) {
		return 0;
	}
	ret = pqcp_runtime_key_store_metadata(
		broker->config.key_store,
		&request->primary_key, &metadata);
	if (ret != 0) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_KEY_OWNERSHIP,
			"key handle not found", ret);
	}
	if (strcmp(metadata.owner, principal->id) != 0) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_KEY_OWNERSHIP,
			"principal does not own key", -EACCES);
	}
	if ((metadata.usage &
	     required_usage(request->operation)) !=
	    required_usage(request->operation)) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_KEY_OWNERSHIP,
			"key usage denied", -EACCES);
	}
	if ((grant->policy.custody_mask &
	     PQCP_CRYPTO_BROKER_CUSTODY_BIT(
		     metadata.custody)) == 0U) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_CUSTODY,
			"key custody denied", -EACCES);
	}
	if (request->operation ==
		    PQCP_CRYPTO_BROKER_OPERATION_EXPORT_PUBLIC &&
	    (!metadata.exportable_public ||
	     !grant->policy.allow_public_export)) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY,
			"public export denied", -EACCES);
	}
	return 0;
}

int pqcp_crypto_broker_authorize(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_crypto_broker_request *request,
	uint64_t now_ms,
	struct pqcp_crypto_broker_authorization *authorization)
{
	struct pqcp_crypto_broker_principal *principal;
	struct pqcp_crypto_broker_grant *grant;
	int principal_index;
	int grant_index = -1;
	int capability_index = -1;
	int ret;

	if (broker == NULL || !broker->initialized ||
	    authorization == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	memset(authorization, 0, sizeof(*authorization));
	ret = pqcp_crypto_broker_internal_validate_request(
		request);
	if (ret != 0) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_POLICY,
			"malformed request", ret);
	}
	if (now_ms < request->submitted_at_ms ||
	    now_ms >= request->deadline_ms) {
		return deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_DEADLINE,
			"request deadline expired", -ETIMEDOUT);
	}
	ret = k_mutex_lock(&broker->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	principal_index =
		pqcp_crypto_broker_internal_principal_index(
			broker, request->principal_id);
	if (principal_index < 0) {
		ret = deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_AUTHENTICATION,
			"unknown principal", -EACCES);
		goto done;
	}
	principal = &broker->storage.principals[principal_index];
	if (principal->state !=
	    PQCP_CRYPTO_BROKER_PRINCIPAL_ACTIVE) {
		ret = deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_AUTHENTICATION,
			"principal inactive", -EKEYREVOKED);
		goto done;
	}
	ret = validate_capability(
		broker, request, now_ms, principal_index,
		&grant_index, &capability_index, authorization);
	if (ret != 0) {
		goto done;
	}
	grant = &broker->storage.grants[grant_index];
	ret = validate_policy_scope(
		broker, request, now_ms, principal, grant,
		authorization);
	if (ret != 0) {
		goto done;
	}
	ret = validate_existing_key(
		broker, request, principal, grant,
		authorization);
	if (ret != 0) {
		goto done;
	}
	if (principal->usage.inflight_requests >=
		    principal->quota.maximum_inflight_requests ||
	    principal->usage.operations >=
		    principal->quota.maximum_operations_per_window ||
	    authorization->cost_units >
		    principal->quota.maximum_cost_units_per_window) {
		ret = deny(
			authorization,
			PQCP_CRYPTO_BROKER_DECISION_DENY_QUOTA,
			"principal quota exhausted", -EDQUOT);
		goto done;
	}
	authorization->principal_index =
		(uint32_t)principal_index;
	authorization->grant_index = (uint32_t)grant_index;
	authorization->capability_index =
		(uint32_t)capability_index;
	authorization->decision =
		PQCP_CRYPTO_BROKER_DECISION_ALLOW;
	(void)pqcp_runtime_internal_copy_text(
		authorization->reason,
		sizeof(authorization->reason), "authorized");
	ret = 0;

done:
	(void)k_mutex_unlock(&broker->lock);
	return ret;
}
