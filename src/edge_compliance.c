/*
 * SPDX-License-Identifier: MIT
 *
 * Canonical compliance snapshot generation and encoding.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

#define COMPLIANCE_ENCODED_BYTES 124U

static uint64_t count_principals(
	struct pqcp_edge_runtime *runtime,
	uint32_t *maximum_risk)
{
	uint64_t count = 0U;

	k_mutex_lock(&runtime->principals.lock,
		     K_FOREVER);
	for (size_t index = 0U;
	     index < runtime->principals.capacity;
	     ++index) {
		const struct pqcp_edge_principal *principal =
			&runtime->principals.principals[index];

		if (principal->state ==
			    PQCP_EDGE_PRINCIPAL_EMPTY ||
		    principal->principal_id[0] == '\0') {
			continue;
		}
		++count;
		if (principal->risk_score > *maximum_risk) {
			*maximum_risk =
				principal->risk_score;
		}
	}
	k_mutex_unlock(&runtime->principals.lock);
	return count;
}

static uint64_t count_services(
	struct pqcp_edge_runtime *runtime)
{
	uint64_t count = 0U;

	k_mutex_lock(&runtime->services.lock, K_FOREVER);
	for (size_t index = 0U;
	     index < runtime->services.service_capacity;
	     ++index) {
		const struct pqcp_edge_service *service =
			&runtime->services.services[index];

		if (service->state !=
			    PQCP_EDGE_SERVICE_EMPTY &&
		    service->service_id[0] != '\0') {
			++count;
		}
	}
	k_mutex_unlock(&runtime->services.lock);
	return count;
}

static uint64_t count_active_sessions(
	struct pqcp_edge_runtime *runtime)
{
	uint64_t count = 0U;

	k_mutex_lock(&runtime->sessions.lock, K_FOREVER);
	for (size_t index = 0U;
	     index < runtime->sessions.capacity; ++index) {
		const struct pqcp_edge_session *session =
			&runtime->sessions.sessions[index];

		if (!session->occupied) {
			continue;
		}
		if (session->state ==
			    PQCP_EDGE_SESSION_ACTIVE ||
		    session->state ==
			    PQCP_EDGE_SESSION_REKEY_REQUIRED ||
		    session->state ==
			    PQCP_EDGE_SESSION_DRAINING) {
			++count;
		}
	}
	k_mutex_unlock(&runtime->sessions.lock);
	return count;
}

static uint64_t count_queued_messages(
	struct pqcp_edge_runtime *runtime)
{
	uint64_t count = 0U;

	k_mutex_lock(&runtime->messages.lock, K_FOREVER);
	for (size_t index = 0U;
	     index < runtime->messages.capacity; ++index) {
		const struct pqcp_edge_message *message =
			&runtime->messages.messages[index];

		if (!message->occupied) {
			continue;
		}
		if (message->state ==
			    PQCP_EDGE_MESSAGE_ACCEPTED ||
		    message->state ==
			    PQCP_EDGE_MESSAGE_QUEUED ||
		    message->state ==
			    PQCP_EDGE_MESSAGE_IN_FLIGHT ||
		    message->state ==
			    PQCP_EDGE_MESSAGE_RETRY_WAIT) {
			++count;
		}
	}
	k_mutex_unlock(&runtime->messages.lock);
	return count;
}

static uint64_t count_vault_objects(
	struct pqcp_edge_runtime *runtime)
{
	uint64_t count = 0U;

	k_mutex_lock(&runtime->vault.lock, K_FOREVER);
	for (size_t index = 0U;
	     index < runtime->vault.capacity; ++index) {
		const struct pqcp_edge_vault_object *object =
			&runtime->vault.objects[index];

		if (!object->occupied) {
			continue;
		}
		if (object->state ==
			    PQCP_EDGE_VAULT_ACTIVE ||
		    object->state ==
			    PQCP_EDGE_VAULT_SEALED ||
		    object->state ==
			    PQCP_EDGE_VAULT_QUARANTINED) {
			++count;
		}
	}
	k_mutex_unlock(&runtime->vault.lock);
	return count;
}

static uint64_t count_open_incidents(
	struct pqcp_edge_runtime *runtime,
	uint32_t *maximum_risk)
{
	uint64_t count = 0U;

	k_mutex_lock(&runtime->incidents.lock,
		     K_FOREVER);
	for (size_t index = 0U;
	     index < runtime->incidents.capacity;
	     ++index) {
		const struct pqcp_edge_incident *incident =
			&runtime->incidents.incidents[index];

		if (!incident->occupied) {
			continue;
		}
		if (incident->state !=
			    PQCP_EDGE_INCIDENT_RESOLVED &&
		    incident->state !=
			    PQCP_EDGE_INCIDENT_CLOSED) {
			++count;
		}
		if (incident->risk_score > *maximum_risk) {
			*maximum_risk =
				incident->risk_score;
		}
	}
	k_mutex_unlock(&runtime->incidents.lock);
	return count;
}

static uint64_t count_posture_risk(
	struct pqcp_edge_runtime *runtime,
	uint32_t *maximum_risk)
{
	uint64_t rejected;

	k_mutex_lock(&runtime->posture.lock, K_FOREVER);
	for (size_t index = 0U;
	     index < runtime->posture.capacity; ++index) {
		const struct pqcp_edge_posture_report *report =
			&runtime->posture.reports[index];

		if (report->occupied &&
		    report->risk_score > *maximum_risk) {
			*maximum_risk = report->risk_score;
		}
	}
	rejected = runtime->posture.rejected_count;
	k_mutex_unlock(&runtime->posture.lock);
	return rejected;
}

static uint64_t count_policy_denials(
	struct pqcp_edge_runtime *runtime)
{
	uint64_t denials = 0U;

	k_mutex_lock(&runtime->principals.lock,
		     K_FOREVER);
	denials = pqcp_edge_internal_saturating_add_u64(
		denials,
		runtime->principals.rejection_count);
	k_mutex_unlock(&runtime->principals.lock);

	k_mutex_lock(&runtime->access.lock, K_FOREVER);
	denials = pqcp_edge_internal_saturating_add_u64(
		denials, runtime->access.deny_count);
	denials = pqcp_edge_internal_saturating_add_u64(
		denials, runtime->access.challenge_count);
	k_mutex_unlock(&runtime->access.lock);

	k_mutex_lock(&runtime->sessions.lock, K_FOREVER);
	denials = pqcp_edge_internal_saturating_add_u64(
		denials,
		runtime->sessions.rejected_count);
	k_mutex_unlock(&runtime->sessions.lock);

	k_mutex_lock(&runtime->traffic.lock, K_FOREVER);
	for (size_t index = 0U;
	     index < runtime->traffic.capacity; ++index) {
		if (runtime->traffic.subjects[index].
			    occupied) {
			denials =
				pqcp_edge_internal_saturating_add_u64(
					denials,
					runtime->traffic.
						subjects[index].
						rejected_requests);
		}
	}
	k_mutex_unlock(&runtime->traffic.lock);

	k_mutex_lock(&runtime->vault.lock, K_FOREVER);
	denials = pqcp_edge_internal_saturating_add_u64(
		denials, runtime->vault.rejection_count);
	k_mutex_unlock(&runtime->vault.lock);

	k_mutex_lock(&runtime->credentials.lock,
		     K_FOREVER);
	denials = pqcp_edge_internal_saturating_add_u64(
		denials,
		runtime->credentials.rejection_count);
	k_mutex_unlock(&runtime->credentials.lock);

	k_mutex_lock(&runtime->isolation.lock,
		     K_FOREVER);
	denials = pqcp_edge_internal_saturating_add_u64(
		denials,
		runtime->isolation.denial_count);
	k_mutex_unlock(&runtime->isolation.lock);

	denials = pqcp_edge_internal_saturating_add_u64(
		denials,
		count_posture_risk(runtime,
			&(uint32_t){0U}));
	return denials;
}

static uint64_t count_integrity_failures(
	struct pqcp_edge_runtime *runtime)
{
	uint64_t failures = 0U;

	if (pqcp_edge_runtime_audit(runtime) != 0) {
		++failures;
	}
	k_mutex_lock(&runtime->messages.lock, K_FOREVER);
	failures = pqcp_edge_internal_saturating_add_u64(
		failures,
		runtime->messages.dead_letter_count);
	k_mutex_unlock(&runtime->messages.lock);

	k_mutex_lock(&runtime->provenance.lock,
		     K_FOREVER);
	failures = pqcp_edge_internal_saturating_add_u64(
		failures,
		runtime->provenance.dropped_count);
	k_mutex_unlock(&runtime->provenance.lock);

	k_mutex_lock(&runtime->scheduler.lock,
		     K_FOREVER);
	failures = pqcp_edge_internal_saturating_add_u64(
		failures,
		runtime->scheduler.failed_count);
	k_mutex_unlock(&runtime->scheduler.lock);
	return failures;
}

static uint32_t calculate_compliance_score(
	const struct pqcp_edge_compliance_summary *summary)
{
	uint64_t penalty = 0U;

	penalty = pqcp_edge_internal_saturating_add_u64(
		penalty,
		summary->integrity_failure_count * 1200U);
	penalty = pqcp_edge_internal_saturating_add_u64(
		penalty,
		summary->open_incident_count * 400U);
	penalty = pqcp_edge_internal_saturating_add_u64(
		penalty,
		summary->policy_denial_count > 1000U ?
			1000U :
			summary->policy_denial_count);
	penalty = pqcp_edge_internal_saturating_add_u64(
		penalty,
		summary->maximum_risk_score > 1000U ?
			1000U :
			summary->maximum_risk_score);
	if (summary->principal_count == 0U ||
	    summary->service_count == 0U) {
		penalty =
			pqcp_edge_internal_saturating_add_u64(
				penalty, 500U);
	}
	return penalty >= 10000U ?
		0U : (uint32_t)(10000U - penalty);
}

static int encode_without_digest(
	const struct pqcp_edge_compliance_summary *summary,
	uint8_t output[COMPLIANCE_ENCODED_BYTES])
{
	size_t offset = 0U;

	if (summary == NULL || output == NULL) {
		return -EINVAL;
	}
	memset(output, 0, COMPLIANCE_ENCODED_BYTES);
	pqcp_edge_internal_write_u32(
		&output[offset], summary->schema_version);
	offset += 4U;
#define WRITE_SUMMARY_U64(field) \
	do { \
		pqcp_edge_internal_write_u64( \
			&output[offset], summary->field); \
		offset += 8U; \
	} while (false)
	WRITE_SUMMARY_U64(generated_at_ms);
	WRITE_SUMMARY_U64(policy_epoch);
	WRITE_SUMMARY_U64(principal_count);
	WRITE_SUMMARY_U64(service_count);
	WRITE_SUMMARY_U64(active_session_count);
	WRITE_SUMMARY_U64(queued_message_count);
	WRITE_SUMMARY_U64(vault_object_count);
	WRITE_SUMMARY_U64(open_incident_count);
	WRITE_SUMMARY_U64(integrity_failure_count);
	WRITE_SUMMARY_U64(policy_denial_count);
#undef WRITE_SUMMARY_U64
	pqcp_edge_internal_write_u32(
		&output[offset],
		summary->maximum_risk_score);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		&output[offset],
		summary->compliance_score);
	offset += 4U;
	memset(&output[offset], 0,
	       PQCP_EDGE_DIGEST_BYTES);
	return 0;
}

int pqcp_edge_compliance_collect(
	struct pqcp_edge_runtime *runtime,
	uint64_t now_ms,
	struct pqcp_edge_compliance_summary *summary)
{
	uint8_t encoded[COMPLIANCE_ENCODED_BYTES];
	int ret;

	if (runtime == NULL || !runtime->initialized ||
	    summary == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	memset(summary, 0, sizeof(*summary));
	summary->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	summary->generated_at_ms = now_ms;
	summary->policy_epoch = runtime->policy_epoch;
	summary->principal_count =
		count_principals(
			runtime,
			&summary->maximum_risk_score);
	summary->service_count =
		count_services(runtime);
	summary->active_session_count =
		count_active_sessions(runtime);
	summary->queued_message_count =
		count_queued_messages(runtime);
	summary->vault_object_count =
		count_vault_objects(runtime);
	summary->open_incident_count =
		count_open_incidents(
			runtime,
			&summary->maximum_risk_score);
	(void)count_posture_risk(
		runtime,
		&summary->maximum_risk_score);
	summary->policy_denial_count =
		count_policy_denials(runtime);
	summary->integrity_failure_count =
		count_integrity_failures(runtime);
	summary->compliance_score =
		calculate_compliance_score(summary);
	ret = encode_without_digest(summary, encoded);
	if (ret != 0) {
		return ret;
	}
	return pqcp_edge_internal_sha256(
		encoded,
		COMPLIANCE_ENCODED_BYTES -
			PQCP_EDGE_DIGEST_BYTES,
		summary->state_digest);
}

int pqcp_edge_compliance_encode(
	const struct pqcp_edge_compliance_summary *summary,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	uint8_t expected[PQCP_EDGE_DIGEST_BYTES];
	int ret;

	if (summary == NULL || output == NULL ||
	    output_length == NULL ||
	    output_capacity < COMPLIANCE_ENCODED_BYTES ||
	    summary->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    summary->generated_at_ms == 0U ||
	    summary->policy_epoch == 0U ||
	    summary->compliance_score > 10000U ||
	    pqcp_edge_internal_all_zero(
		    summary->state_digest,
		    sizeof(summary->state_digest))) {
		return -EINVAL;
	}
	ret = encode_without_digest(summary, output);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_edge_internal_sha256(
		output,
		COMPLIANCE_ENCODED_BYTES -
			PQCP_EDGE_DIGEST_BYTES,
		expected);
	if (ret != 0) {
		return ret;
	}
	if (!pqcp_edge_internal_equal(
		    expected,
		    summary->state_digest,
		    sizeof(expected))) {
		memset(output, 0,
		       COMPLIANCE_ENCODED_BYTES);
		return -EBADMSG;
	}
	memcpy(&output[COMPLIANCE_ENCODED_BYTES -
		       PQCP_EDGE_DIGEST_BYTES],
	       summary->state_digest,
	       sizeof(summary->state_digest));
	*output_length = COMPLIANCE_ENCODED_BYTES;
	return 0;
}
