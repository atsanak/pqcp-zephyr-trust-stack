/*
 * SPDX-License-Identifier: MIT
 *
 * RFC 9334 RATS freshness, evidence appraisal, and relying-party policy.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/fleet_eat.h>

#define RATS_REASON_NONCE (UINT32_C(1) << 0)
#define RATS_REASON_FUTURE (UINT32_C(1) << 1)
#define RATS_REASON_EXPIRED (UINT32_C(1) << 2)
#define RATS_REASON_TOO_OLD (UINT32_C(1) << 3)
#define RATS_REASON_PROFILE (UINT32_C(1) << 4)
#define RATS_REASON_RISK (UINT32_C(1) << 5)
#define RATS_REASON_POLICY_EPOCH (UINT32_C(1) << 6)
#define RATS_REASON_REVOCATION_EPOCH (UINT32_C(1) << 7)
#define RATS_REASON_CAPABILITIES (UINT32_C(1) << 8)
#define RATS_REASON_DEBUG (UINT32_C(1) << 9)
#define RATS_REASON_BOOT (UINT32_C(1) << 10)
#define RATS_REASON_FIRMWARE (UINT32_C(1) << 11)
#define RATS_REASON_POLICY_DIGEST (UINT32_C(1) << 12)
#define RATS_REASON_CHANNEL (UINT32_C(1) << 13)
#define RATS_REASON_MEASUREMENT (UINT32_C(1) << 14)
#define RATS_REASON_UNKNOWN_MEASUREMENT (UINT32_C(1) << 15)
#define RATS_REASON_REVOKED (UINT32_C(1) << 16)
#define RATS_REASON_LOCKDOWN (UINT32_C(1) << 17)
#define RATS_REASON_ROLE (UINT32_C(1) << 18)
#define RATS_REASON_RESULT (UINT32_C(1) << 19)

static size_t bounded_length(
	const char *value,
	size_t capacity)
{
	size_t length = 0U;

	if (value == NULL) {
		return 0U;
	}
	while (length < capacity && value[length] != '\0') {
		length++;
	}
	return length;
}

static bool constant_time_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	if ((left == NULL || right == NULL) && length != 0U) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static void add_advice(
	struct pqcp_fleet_eat_appraisal_result *result,
	enum pqcp_fleet_eat_advice advice)
{
	if (result == NULL || advice == PQCP_FLEET_EAT_ADVICE_NONE) {
		return;
	}
	for (size_t index = 0U;
	     index < result->advice_count; ++index) {
		if (result->advice[index] == advice) {
			return;
		}
	}
	if (result->advice_count < PQCP_FLEET_EAT_MAX_ADVICE) {
		result->advice[result->advice_count++] = advice;
	}
}

static int freshness_reason(
	const struct pqcp_fleet_eat_claims *claims,
	const struct pqcp_fleet_eat_freshness *freshness,
	uint32_t *reason)
{
	uint64_t future_limit;

	if (claims == NULL || freshness == NULL ||
	    reason == NULL || freshness->now == 0U ||
	    freshness->expected_nonce_length >
		    PQCP_FLEET_EAT_NONCE_MAX_BYTES ||
	    (freshness->expected_nonce == NULL &&
	     freshness->expected_nonce_length != 0U)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	*reason = 0U;
	if (freshness->require_nonce) {
		if (freshness->expected_nonce_length == 0U ||
		    claims->nonce_length !=
			    freshness->expected_nonce_length ||
		    !constant_time_equal(
			    claims->nonce,
			    freshness->expected_nonce,
			    claims->nonce_length)) {
			*reason |= RATS_REASON_NONCE;
		}
	}
	if (freshness->require_expiration &&
	    !claims->expiration_present) {
		*reason |= RATS_REASON_EXPIRED;
	}
	future_limit =
		UINT64_MAX - freshness->maximum_future_skew <
				freshness->now ?
			UINT64_MAX :
			freshness->now +
				freshness->maximum_future_skew;
	if (claims->issued_at_present) {
		if (claims->issued_at > future_limit) {
			*reason |= RATS_REASON_FUTURE;
		} else if (freshness->maximum_age != 0U &&
			   claims->issued_at < freshness->now &&
			   freshness->now - claims->issued_at >
				   freshness->maximum_age) {
			*reason |= RATS_REASON_TOO_OLD;
		}
	} else if (freshness->maximum_age != 0U) {
		*reason |= RATS_REASON_TOO_OLD;
	}
	if (claims->not_before_present &&
	    claims->not_before > future_limit) {
		*reason |= RATS_REASON_FUTURE;
	}
	if (claims->expiration_present &&
	    claims->expiration <= freshness->now) {
		*reason |= RATS_REASON_EXPIRED;
	}
	return 0;
}

int pqcp_fleet_eat_freshness_check(
	const struct pqcp_fleet_eat_claims *claims,
	const struct pqcp_fleet_eat_freshness *freshness)
{
	uint32_t reason;
	int ret = pqcp_fleet_eat_claims_validate(claims);

	if (ret != 0) {
		return ret;
	}
	ret = freshness_reason(claims, freshness, &reason);
	if (ret != 0) {
		return ret;
	}
	return reason == 0U ? 0 :
		PQCP_FLEET_COSE_ERR_POLICY;
}

static void appraise_measurements(
	const struct pqcp_fleet_eat_claims *evidence,
	const struct pqcp_fleet_eat_appraisal_policy *policy,
	struct pqcp_fleet_eat_appraisal_result *result)
{
	for (size_t index = 0U;
	     index < evidence->measurement_count; ++index) {
		const struct pqcp_fleet_eat_measurement *measurement =
			&evidence->measurements[index];

		switch (measurement->result) {
		case PQCP_FLEET_EAT_MEASUREMENT_SUCCESS:
			result->accepted_measurements++;
			break;
		case PQCP_FLEET_EAT_MEASUREMENT_FAILURE:
			result->failed_measurements++;
			if (policy->reject_failed_measurements) {
				result->reason_mask |=
					RATS_REASON_MEASUREMENT;
			}
			break;
		case PQCP_FLEET_EAT_MEASUREMENT_NOT_RUN:
		case PQCP_FLEET_EAT_MEASUREMENT_ABSENT:
			result->missing_measurements++;
			if (policy->reject_unknown_measurements) {
				result->reason_mask |=
					RATS_REASON_UNKNOWN_MEASUREMENT;
			}
			break;
		default:
			result->reason_mask |=
				RATS_REASON_UNKNOWN_MEASUREMENT;
			break;
		}
	}
	if (evidence->measurement_count == 0U &&
	    policy->reject_unknown_measurements) {
		result->reason_mask |=
			RATS_REASON_UNKNOWN_MEASUREMENT;
	}
}

static void appraise_posture(
	const struct pqcp_fleet_eat_claims *evidence,
	const struct pqcp_fleet_eat_appraisal_policy *policy,
	struct pqcp_fleet_eat_appraisal_result *result)
{
	if (evidence->risk_score_present &&
	    evidence->risk_score > policy->maximum_risk_score) {
		result->reason_mask |= RATS_REASON_RISK;
	}
	if (policy->minimum_policy_epoch != 0U &&
	    (!evidence->policy_epoch_present ||
	     evidence->policy_epoch <
		     policy->minimum_policy_epoch)) {
		result->reason_mask |= RATS_REASON_POLICY_EPOCH;
	}
	if (policy->minimum_revocation_epoch != 0U &&
	    (!evidence->revocation_epoch_present ||
	     evidence->revocation_epoch <
		     policy->minimum_revocation_epoch)) {
		result->reason_mask |=
			RATS_REASON_REVOCATION_EPOCH;
	}
	if (policy->required_capabilities != 0U &&
	    (!evidence->capabilities_present ||
	     (evidence->capabilities &
	      policy->required_capabilities) !=
		     policy->required_capabilities)) {
		result->reason_mask |= RATS_REASON_CAPABILITIES;
	}
	if (evidence->debug_status_present &&
	    evidence->debug_status <
		    policy->maximum_debug_status) {
		result->reason_mask |= RATS_REASON_DEBUG;
	}
	if (policy->require_oem_boot && !evidence->oem_boot) {
		result->reason_mask |= RATS_REASON_BOOT;
	}
	if (policy->require_firmware_digest &&
	    evidence->firmware_digest_length !=
		    PQCP_FLEET_EAT_DIGEST_BYTES) {
		result->reason_mask |= RATS_REASON_FIRMWARE;
	}
	if (policy->require_policy_digest &&
	    evidence->policy_digest_length !=
		    PQCP_FLEET_EAT_DIGEST_BYTES) {
		result->reason_mask |=
			RATS_REASON_POLICY_DIGEST;
	}
	if (policy->require_channel_binding &&
	    evidence->channel_binding_length !=
		    PQCP_FLEET_EAT_DIGEST_BYTES) {
		result->reason_mask |= RATS_REASON_CHANNEL;
	}
	if (evidence->runtime_state_present &&
	    evidence->runtime_state ==
		    PQCP_FLEET_EAT_RUNTIME_REVOKED) {
		result->reason_mask |= RATS_REASON_REVOKED;
	}
	if (evidence->runtime_state_present &&
	    evidence->runtime_state ==
		    PQCP_FLEET_EAT_RUNTIME_LOCKDOWN) {
		result->reason_mask |= RATS_REASON_LOCKDOWN;
	}
}

static void choose_appraisal(
	struct pqcp_fleet_eat_appraisal_result *result)
{
	if ((result->reason_mask & RATS_REASON_REVOKED) != 0U) {
		result->appraisal =
			PQCP_FLEET_EAT_APPRAISAL_REVOKED;
		add_advice(
			result, PQCP_FLEET_EAT_ADVICE_REENROLL);
		add_advice(
			result, PQCP_FLEET_EAT_ADVICE_ISOLATE);
		return;
	}
	if ((result->reason_mask &
	     (RATS_REASON_FUTURE |
	      RATS_REASON_EXPIRED |
	      RATS_REASON_TOO_OLD |
	      RATS_REASON_NONCE)) != 0U) {
		result->appraisal =
			PQCP_FLEET_EAT_APPRAISAL_STALE;
		add_advice(
			result, PQCP_FLEET_EAT_ADVICE_REMEDIATE);
		return;
	}
	if ((result->reason_mask &
	     (RATS_REASON_DEBUG |
	      RATS_REASON_BOOT |
	      RATS_REASON_FIRMWARE |
	      RATS_REASON_MEASUREMENT |
	      RATS_REASON_LOCKDOWN)) != 0U) {
		result->appraisal =
			PQCP_FLEET_EAT_APPRAISAL_QUARANTINE;
		add_advice(
			result, PQCP_FLEET_EAT_ADVICE_ISOLATE);
		add_advice(
			result, PQCP_FLEET_EAT_ADVICE_LOCKDOWN);
		return;
	}
	if (result->reason_mask != 0U) {
		result->appraisal =
			PQCP_FLEET_EAT_APPRAISAL_UNTRUSTED;
		add_advice(
			result, PQCP_FLEET_EAT_ADVICE_LIMIT);
		add_advice(
			result, PQCP_FLEET_EAT_ADVICE_REMEDIATE);
		return;
	}
	result->appraisal =
		PQCP_FLEET_EAT_APPRAISAL_TRUSTED;
	add_advice(result, PQCP_FLEET_EAT_ADVICE_ALLOW);
}

int pqcp_fleet_eat_appraise_evidence(
	const struct pqcp_fleet_eat_claims *evidence,
	const struct pqcp_fleet_eat_appraisal_policy *policy,
	struct pqcp_fleet_eat_appraisal_result *result)
{
	int ret;

	if (policy == NULL || result == NULL ||
	    policy->maximum_debug_status >
		    PQCP_FLEET_EAT_DEBUG_DISABLED_FULLY_AND_PERMANENTLY) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_eat_claims_validate(evidence);
	if (ret != 0) {
		return ret;
	}
	memset(result, 0, sizeof(*result));
	if (evidence->role != PQCP_FLEET_EAT_ROLE_EVIDENCE) {
		result->reason_mask |= RATS_REASON_ROLE;
	}
	if (strcmp(
		    evidence->profile,
		    PQCP_FLEET_EAT_PROFILE_URI) != 0) {
		result->reason_mask |= RATS_REASON_PROFILE;
	}
	appraise_posture(evidence, policy, result);
	appraise_measurements(evidence, policy, result);
	choose_appraisal(result);
	return 0;
}

static int copy_text_field(
	char *output,
	size_t capacity,
	const char *value)
{
	const size_t length = bounded_length(value, capacity);

	if (output == NULL || value == NULL ||
	    length == 0U || length >= capacity) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	memcpy(output, value, length);
	output[length] = '\0';
	return 0;
}

int pqcp_fleet_eat_make_result(
	const struct pqcp_fleet_eat_claims *evidence,
	const struct pqcp_fleet_eat_appraisal_result *appraisal,
	const uint8_t evidence_digest[PQCP_FLEET_EAT_DIGEST_BYTES],
	const char *verifier_id,
	const char *audience,
	uint64_t issued_at,
	uint64_t expiration,
	struct pqcp_fleet_eat_claims *result_claims)
{
	int ret;

	if (evidence == NULL || appraisal == NULL ||
	    evidence_digest == NULL || verifier_id == NULL ||
	    audience == NULL || result_claims == NULL ||
	    issued_at == 0U || expiration <= issued_at ||
	    evidence->role != PQCP_FLEET_EAT_ROLE_EVIDENCE ||
	    appraisal->appraisal <
		    PQCP_FLEET_EAT_APPRAISAL_TRUSTED ||
	    appraisal->appraisal >
		    PQCP_FLEET_EAT_APPRAISAL_QUARANTINE ||
	    appraisal->advice_count >
		    PQCP_FLEET_EAT_MAX_ADVICE) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	memset(result_claims, 0, sizeof(*result_claims));
	result_claims->role =
		PQCP_FLEET_EAT_ROLE_ATTESTATION_RESULT;
	memcpy(
		result_claims->nonce, evidence->nonce,
		evidence->nonce_length);
	result_claims->nonce_length = evidence->nonce_length;
	memcpy(
		result_claims->ueid, evidence->ueid,
		evidence->ueid_length);
	result_claims->ueid_length = evidence->ueid_length;
	ret = copy_text_field(
		result_claims->issuer,
		sizeof(result_claims->issuer), verifier_id);
	if (ret == 0) {
		ret = copy_text_field(
			result_claims->audience,
			sizeof(result_claims->audience),
			audience);
	}
	if (ret == 0) {
		ret = copy_text_field(
			result_claims->profile,
			sizeof(result_claims->profile),
			PQCP_FLEET_EAT_PROFILE_URI);
	}
	if (ret != 0) {
		memset(result_claims, 0, sizeof(*result_claims));
		return ret;
	}
	result_claims->issued_at = issued_at;
	result_claims->issued_at_present = true;
	result_claims->expiration = expiration;
	result_claims->expiration_present = true;
	result_claims->appraisal = appraisal->appraisal;
	result_claims->appraisal_present = true;
	result_claims->result_reason = appraisal->reason_mask;
	result_claims->result_reason_present = true;
	memcpy(
		result_claims->evidence_digest,
		evidence_digest,
		PQCP_FLEET_EAT_DIGEST_BYTES);
	result_claims->evidence_digest_length =
		PQCP_FLEET_EAT_DIGEST_BYTES;
	for (size_t index = 0U;
	     index < appraisal->advice_count; ++index) {
		result_claims->advice[index] =
			appraisal->advice[index];
	}
	result_claims->advice_count = appraisal->advice_count;
	if (evidence->policy_epoch_present) {
		result_claims->policy_epoch =
			evidence->policy_epoch;
		result_claims->policy_epoch_present = true;
	}
	if (evidence->revocation_epoch_present) {
		result_claims->revocation_epoch =
			evidence->revocation_epoch;
		result_claims->revocation_epoch_present = true;
	}
	if (evidence->credential_epoch_present) {
		result_claims->credential_epoch =
			evidence->credential_epoch;
		result_claims->credential_epoch_present = true;
	}
	if (evidence->capabilities_present) {
		result_claims->capabilities =
			evidence->capabilities;
		result_claims->capabilities_present = true;
	}
	if (evidence->reference_set_present) {
		result_claims->reference_set =
			evidence->reference_set;
		result_claims->reference_set_present = true;
	}
	if (evidence->risk_score_present) {
		result_claims->risk_score =
			evidence->risk_score;
		result_claims->risk_score_present = true;
	}
	if (evidence->runtime_state_present) {
		result_claims->runtime_state =
			evidence->runtime_state;
		result_claims->runtime_state_present = true;
	}
	result_claims->oem_boot = evidence->oem_boot;
	return pqcp_fleet_eat_claims_validate(result_claims);
}

int pqcp_fleet_eat_result_authorize(
	const struct pqcp_fleet_eat_claims *result_claims,
	const struct pqcp_fleet_eat_appraisal_policy *relying_policy,
	struct pqcp_fleet_eat_appraisal_result *result)
{
	int ret;

	if (relying_policy == NULL || result == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_eat_claims_validate(result_claims);
	if (ret != 0) {
		return ret;
	}
	memset(result, 0, sizeof(*result));
	if (result_claims->role !=
		    PQCP_FLEET_EAT_ROLE_ATTESTATION_RESULT) {
		result->reason_mask |= RATS_REASON_ROLE;
	}
	if (!result_claims->appraisal_present ||
	    result_claims->appraisal !=
		    PQCP_FLEET_EAT_APPRAISAL_TRUSTED) {
		result->reason_mask |= RATS_REASON_RESULT;
	}
	appraise_posture(
		result_claims, relying_policy, result);
	if (result->reason_mask == 0U) {
		result->appraisal =
			PQCP_FLEET_EAT_APPRAISAL_TRUSTED;
		add_advice(
			result, PQCP_FLEET_EAT_ADVICE_ALLOW);
	} else if (result_claims->appraisal ==
		   PQCP_FLEET_EAT_APPRAISAL_REVOKED) {
		result->appraisal =
			PQCP_FLEET_EAT_APPRAISAL_REVOKED;
		add_advice(
			result, PQCP_FLEET_EAT_ADVICE_ISOLATE);
	} else {
		result->appraisal =
			PQCP_FLEET_EAT_APPRAISAL_UNTRUSTED;
		add_advice(
			result, PQCP_FLEET_EAT_ADVICE_LIMIT);
	}
	return 0;
}

const char *pqcp_fleet_eat_role_string(
	enum pqcp_fleet_eat_role role)
{
	switch (role) {
	case PQCP_FLEET_EAT_ROLE_EVIDENCE:
		return "evidence";
	case PQCP_FLEET_EAT_ROLE_ATTESTATION_RESULT:
		return "attestation-result";
	default:
		return "none";
	}
}

const char *pqcp_fleet_eat_appraisal_string(
	enum pqcp_fleet_eat_appraisal appraisal)
{
	switch (appraisal) {
	case PQCP_FLEET_EAT_APPRAISAL_INDETERMINATE:
		return "indeterminate";
	case PQCP_FLEET_EAT_APPRAISAL_TRUSTED:
		return "trusted";
	case PQCP_FLEET_EAT_APPRAISAL_UNTRUSTED:
		return "untrusted";
	case PQCP_FLEET_EAT_APPRAISAL_STALE:
		return "stale";
	case PQCP_FLEET_EAT_APPRAISAL_REVOKED:
		return "revoked";
	case PQCP_FLEET_EAT_APPRAISAL_QUARANTINE:
		return "quarantine";
	default:
		return "unknown";
	}
}
