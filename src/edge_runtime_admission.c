/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * End-to-end zero-trust admission composition.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool request_valid(
	const struct pqcp_edge_admission_request *request)
{
	if (request == NULL ||
	    !pqcp_edge_internal_text_valid(
		    request->principal_id,
		    sizeof(request->principal_id)) ||
	    !pqcp_edge_internal_text_valid(
		    request->service_id,
		    sizeof(request->service_id)) ||
	    request->operation <=
		    PQCP_EDGE_OPERATION_NONE ||
	    request->operation >=
		    PQCP_EDGE_OPERATION_COUNT ||
	    request->required_capabilities == 0U ||
	    request->revocation_epoch == 0U ||
	    request->now_ms == 0U) {
		return false;
	}
	if (request->require_credential &&
	    !pqcp_edge_internal_text_valid(
		    request->credential_id,
		    sizeof(request->credential_id))) {
		return false;
	}
	if (request->endpoint_id[0] != '\0' &&
	    !pqcp_edge_internal_text_valid(
		    request->endpoint_id,
		    sizeof(request->endpoint_id))) {
		return false;
	}
	return true;
}

static void set_rejection(
	struct pqcp_edge_admission_result *result,
	enum pqcp_edge_policy_reason reason,
	const char *explanation)
{
	result->access.effect = PQCP_EDGE_POLICY_DENY;
	result->access.reason = reason;
	(void)pqcp_edge_internal_copy_text(
		result->access.explanation,
		sizeof(result->access.explanation),
		explanation);
	result->admitted = false;
}

static int lookup_subjects(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_admission_request *request,
	struct pqcp_edge_principal **principal,
	struct pqcp_edge_service **service)
{
	int ret;

	ret = pqcp_edge_principal_find(
		&runtime->principals,
		request->principal_id,
		principal);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_service_find(
		&runtime->services,
		request->service_id,
		service);
	if (ret != 0) {
		return ret;
	}
	if ((*principal)->state !=
		    PQCP_EDGE_PRINCIPAL_ACTIVE &&
	    (*principal)->state !=
		    PQCP_EDGE_PRINCIPAL_DEGRADED) {
		return -EACCES;
	}
	if ((*service)->state !=
		    PQCP_EDGE_SERVICE_HEALTHY &&
	    (*service)->state !=
		    PQCP_EDGE_SERVICE_REGISTERED) {
		return -EHOSTDOWN;
	}
	if ((*principal)->policy_epoch <
		    runtime->policy_epoch ||
	    (*service)->policy_epoch <
		    runtime->policy_epoch) {
		return -ESTALE;
	}
	if ((*principal)->revocation_epoch <
	    request->revocation_epoch) {
		return -EKEYREVOKED;
	}
	return 0;
}

static int evaluate_posture(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_admission_request *request,
	struct pqcp_edge_admission_result *result)
{
	int ret;

	ret = pqcp_edge_posture_evaluate(
		&runtime->posture,
		request->principal_id,
		request->now_ms,
		&result->posture_effect,
		&result->posture_failure_mask,
		&result->posture_risk_score);
	if (ret != 0) {
		result->posture_effect =
			PQCP_EDGE_POLICY_CHALLENGE;
		return ret;
	}
	if (result->posture_effect ==
		    PQCP_EDGE_POLICY_DENY ||
	    result->posture_effect ==
		    PQCP_EDGE_POLICY_QUARANTINE) {
		return -EACCES;
	}
	if (result->posture_effect ==
	    PQCP_EDGE_POLICY_CHALLENGE) {
		return -EAGAIN;
	}
	return 0;
}

static int evaluate_attestation(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_admission_request *request,
	const struct pqcp_edge_service *service,
	struct pqcp_edge_admission_result *result)
{
	bool fresh = false;
	int ret;

	if (!service->require_attestation) {
		result->attestation_fresh = false;
		return 0;
	}
	ret = pqcp_edge_attestation_is_fresh(
		&runtime->attestation,
		request->principal_id,
		request->now_ms,
		&fresh);
	if (ret != 0) {
		return ret;
	}
	result->attestation_fresh = fresh;
	return fresh ? 0 : -EKEYEXPIRED;
}

static int evaluate_credential(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_admission_request *request)
{
	if (!request->require_credential) {
		return 0;
	}
	return pqcp_edge_credential_authorize(
		&runtime->credentials,
		request->credential_id,
		request->principal_id,
		request->required_capabilities,
		runtime->policy_epoch,
		request->revocation_epoch,
		request->now_ms);
}

static int evaluate_isolation(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_admission_request *request,
	const struct pqcp_edge_principal *principal)
{
	return pqcp_edge_isolation_authorize(
		&runtime->isolation,
		principal->zone,
		request->operation,
		request->required_capabilities,
		request->now_ms);
}

static int evaluate_access_policy(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_admission_request *request,
	const struct pqcp_edge_principal *principal,
	const struct pqcp_edge_service *service,
	struct pqcp_edge_admission_result *result)
{
	struct pqcp_edge_access_context context;
	int ret;

	memset(&context, 0, sizeof(context));
	context.principal = principal;
	context.service = service;
	context.operation = request->operation;
	context.now_ms = request->now_ms;
	context.current_concurrent =
		request->current_concurrent;
	context.channel_identity_verified =
		request->channel_identity_verified;
	context.attestation_fresh =
		result->attestation_fresh;
	ret = pqcp_edge_internal_copy_text(
		context.source_zone,
		sizeof(context.source_zone),
		principal->zone);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_internal_copy_text(
		context.destination_zone,
		sizeof(context.destination_zone),
		service->zone);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_access_evaluate(
		&runtime->access,
		&context,
		&result->access);
	if (ret != 0) {
		return ret;
	}
	if (result->access.effect ==
		    PQCP_EDGE_POLICY_ALLOW) {
		return 0;
	}
	if (result->access.effect ==
		    PQCP_EDGE_POLICY_CHALLENGE) {
		return -EAGAIN;
	}
	return -EACCES;
}

static int evaluate_circuit(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_admission_request *request)
{
	if (request->endpoint_id[0] == '\0') {
		return 0;
	}
	return pqcp_edge_circuit_allow(
		&runtime->circuits,
		request->service_id,
		request->endpoint_id,
		request->now_ms);
}

static int reserve_traffic(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_admission_request *request)
{
	if (!request->reserve_traffic) {
		return 0;
	}
	return pqcp_edge_traffic_authorize(
		&runtime->traffic,
		request->principal_id,
		request->service_id,
		request->request_bytes,
		request->now_ms);
}

int pqcp_edge_runtime_authorize(
	struct pqcp_edge_runtime *runtime,
	const struct pqcp_edge_admission_request *request,
	struct pqcp_edge_admission_result *result)
{
	struct pqcp_edge_principal *principal = NULL;
	struct pqcp_edge_service *service = NULL;
	int ret;

	if (runtime == NULL || !runtime->initialized ||
	    !request_valid(request) || result == NULL) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	result->access.effect = PQCP_EDGE_POLICY_DENY;
	result->access.reason =
		PQCP_EDGE_POLICY_REASON_DEFAULT;

	ret = lookup_subjects(
		runtime, request, &principal, &service);
	if (ret != 0) {
		set_rejection(
			result,
			ret == -ESTALE ||
				ret == -EKEYREVOKED ?
				PQCP_EDGE_POLICY_REASON_REVOCATION :
				PQCP_EDGE_POLICY_REASON_PRINCIPAL,
			"principal or service is not eligible");
		return ret;
	}
	if ((principal->capabilities &
	     request->required_capabilities) !=
	    request->required_capabilities) {
		set_rejection(
			result,
			PQCP_EDGE_POLICY_REASON_CAPABILITY,
			"principal lacks required capabilities");
		return -EACCES;
	}

	result->credential_result =
		evaluate_credential(runtime, request);
	if (result->credential_result != 0) {
		set_rejection(
			result,
			PQCP_EDGE_POLICY_REASON_REVOCATION,
			"credential validation failed");
		return result->credential_result;
	}

	result->isolation_result =
		evaluate_isolation(
			runtime, request, principal);
	if (result->isolation_result != 0) {
		set_rejection(
			result,
			PQCP_EDGE_POLICY_REASON_ZONE,
			"isolation zone rejected operation");
		return result->isolation_result;
	}

	ret = evaluate_posture(runtime, request, result);
	if (ret != 0) {
		set_rejection(
			result,
			PQCP_EDGE_POLICY_REASON_ATTESTATION,
			"workload posture is insufficient");
		return ret;
	}

	result->attestation_result =
		evaluate_attestation(
			runtime, request, service, result);
	if (result->attestation_result != 0) {
		set_rejection(
			result,
			PQCP_EDGE_POLICY_REASON_ATTESTATION,
			"fresh attestation is required");
		return result->attestation_result;
	}

	ret = evaluate_access_policy(
		runtime, request, principal, service, result);
	if (ret != 0) {
		return ret;
	}

	result->circuit_result =
		evaluate_circuit(runtime, request);
	if (result->circuit_result != 0) {
		set_rejection(
			result,
			PQCP_EDGE_POLICY_REASON_SERVICE,
			"service endpoint circuit is unavailable");
		return result->circuit_result;
	}

	result->traffic_result =
		reserve_traffic(runtime, request);
	if (result->traffic_result != 0) {
		set_rejection(
			result,
			PQCP_EDGE_POLICY_REASON_QUOTA,
			"traffic policy rejected reservation");
		return result->traffic_result;
	}
	result->admitted = true;
	return 0;
}

int pqcp_edge_runtime_complete_request(
	struct pqcp_edge_runtime *runtime,
	const char *principal_id,
	const char *service_id,
	const char *endpoint_id,
	bool success,
	uint64_t latency_us,
	uint64_t now_ms)
{
	int first_error = 0;
	int ret;

	if (runtime == NULL || !runtime->initialized ||
	    principal_id == NULL || service_id == NULL ||
	    now_ms == 0U ||
	    !pqcp_edge_internal_text_valid(
		    principal_id,
		    PQCP_EDGE_ID_MAX_CHARS) ||
	    !pqcp_edge_internal_text_valid(
		    service_id,
		    PQCP_EDGE_ID_MAX_CHARS)) {
		return -EINVAL;
	}
	if (endpoint_id != NULL &&
	    endpoint_id[0] != '\0' &&
	    !pqcp_edge_internal_text_valid(
		    endpoint_id,
		    PQCP_EDGE_ID_MAX_CHARS)) {
		return -EINVAL;
	}
	ret = pqcp_edge_traffic_complete(
		&runtime->traffic,
		principal_id,
		service_id,
		success,
		now_ms);
	if (ret != 0) {
		first_error = ret;
	}
	if (endpoint_id != NULL &&
	    endpoint_id[0] != '\0') {
		ret = pqcp_edge_circuit_record(
			&runtime->circuits,
			service_id,
			endpoint_id,
			success,
			now_ms);
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
		ret = pqcp_edge_endpoint_observe(
			&runtime->services,
			endpoint_id,
			success,
			latency_us > UINT32_MAX ?
				UINT32_MAX :
				(uint32_t)latency_us,
			now_ms);
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
	}
	ret = pqcp_edge_sla_record(
		&runtime->sla,
		service_id,
		success,
		latency_us,
		now_ms);
	if (ret != 0 && ret != -ENOENT &&
	    first_error == 0) {
		first_error = ret;
	}
	return first_error;
}
