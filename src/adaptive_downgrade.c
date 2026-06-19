/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Explicit security downgrade authorization for adaptive PQC transitions.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_DOWNGRADE_AUTH_DOMAIN UINT64_C(0x414450444f574e41)
#define PQCP_ADAPTIVE_DOWNGRADE_RESULT_DOMAIN UINT64_C(0x414450444f574e52)

static bool reason_valid(enum pqcp_adaptive_transition_reason reason)
{
	return reason >= PQCP_ADAPTIVE_REASON_NONE &&
	       reason <= PQCP_ADAPTIVE_REASON_ROLLBACK;
}

static uint32_t reason_bit(
	enum pqcp_adaptive_transition_reason reason)
{
	if (!reason_valid(reason) || reason == PQCP_ADAPTIVE_REASON_NONE) {
		return 0U;
	}
	return 1U << ((uint32_t)reason - 1U);
}

static int authorization_digest(
	const struct pqcp_adaptive_downgrade_authorization *authorization,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	if (authorization == NULL || output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_DOWNGRADE_AUTH_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, authorization->schema_version);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, authorization->issued_at_ms);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, authorization->expires_at_ms);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, authorization->minimum_security_level);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, authorization->maximum_security_drop);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, authorization->allowed_reason_mask);
	pqcp_deployment_evidence_digest_update_text(
		&digest, authorization->device_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, authorization->from_profile_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, authorization->to_profile_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, authorization->nonce_hex);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, authorization->approved);
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, output);
}

static bool authorization_valid(
	const struct pqcp_adaptive_downgrade_authorization *authorization,
	const struct pqcp_adaptive_profile *from,
	const struct pqcp_adaptive_profile *to,
	enum pqcp_adaptive_transition_reason reason,
	uint64_t now_ms,
	uint32_t security_drop)
{
	char expected[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];

	if (authorization == NULL ||
	    authorization->schema_version !=
		    PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !authorization->approved || authorization->consumed ||
	    authorization->issued_at_ms > now_ms ||
	    authorization->expires_at_ms < now_ms ||
	    authorization->expires_at_ms <
		    authorization->issued_at_ms ||
	    authorization->minimum_security_level >
		    to->security_level ||
	    authorization->maximum_security_drop < security_drop ||
	    (authorization->allowed_reason_mask &
	     reason_bit(reason)) == 0U ||
	    strcmp(authorization->from_profile_id,
		   from->profile_id) != 0 ||
	    strcmp(authorization->to_profile_id,
		   to->profile_id) != 0 ||
	    !pqcp_deployment_evidence_codec_is_lower_hex(
		    authorization->nonce_hex, 32U) ||
	    authorization_digest(authorization, expected) != 0) {
		return false;
	}
	return strcmp(expected,
		      authorization->authorization_digest_hex) == 0;
}

static int result_digest(
	const struct pqcp_adaptive_downgrade_result *result,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_DOWNGRADE_RESULT_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, (uint32_t)result->status);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->blocker_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->warning_mask);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, result->security_drop);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->downgrade);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->authorization_required);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->authorization_valid);
	pqcp_deployment_evidence_digest_update_bool(
		&digest, result->consumed);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->from_profile_id);
	pqcp_deployment_evidence_digest_update_text(
		&digest, result->to_profile_id);
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, output);
}

int pqcp_adaptive_downgrade_authorization_build(
	const char *device_id,
	const struct pqcp_adaptive_profile *from,
	const struct pqcp_adaptive_profile *to,
	enum pqcp_adaptive_transition_reason reason,
	uint64_t issued_at_ms,
	uint64_t expires_at_ms,
	const char *nonce_hex,
	struct pqcp_adaptive_downgrade_authorization *authorization)
{
	uint32_t from_strength;
	uint32_t to_strength;

	if (!pqcp_adaptive_internal_id_valid(device_id) ||
	    !pqcp_adaptive_internal_profile_valid(from) ||
	    !pqcp_adaptive_internal_profile_valid(to) ||
	    !reason_valid(reason) ||
	    reason == PQCP_ADAPTIVE_REASON_NONE ||
	    issued_at_ms == 0U || expires_at_ms <= issued_at_ms ||
	    !pqcp_deployment_evidence_codec_is_lower_hex(
		    nonce_hex, 32U) ||
	    authorization == NULL) {
		return -EINVAL;
	}
	from_strength =
		pqcp_adaptive_internal_profile_security_strength(from);
	to_strength =
		pqcp_adaptive_internal_profile_security_strength(to);
	if (to_strength >= from_strength) {
		return -EALREADY;
	}
	memset(authorization, 0, sizeof(*authorization));
	authorization->schema_version =
		PQCP_ADAPTIVE_SCHEMA_VERSION;
	authorization->issued_at_ms = issued_at_ms;
	authorization->expires_at_ms = expires_at_ms;
	authorization->minimum_security_level =
		to->security_level;
	authorization->maximum_security_drop =
		from->security_level > to->security_level ?
		from->security_level - to->security_level : 0U;
	authorization->allowed_reason_mask = reason_bit(reason);
	pqcp_adaptive_internal_set_text(
		authorization->device_id,
		sizeof(authorization->device_id), device_id);
	pqcp_adaptive_internal_set_text(
		authorization->from_profile_id,
		sizeof(authorization->from_profile_id),
		from->profile_id);
	pqcp_adaptive_internal_set_text(
		authorization->to_profile_id,
		sizeof(authorization->to_profile_id),
		to->profile_id);
	pqcp_adaptive_internal_set_text(
		authorization->nonce_hex,
		sizeof(authorization->nonce_hex), nonce_hex);
	authorization->approved = true;
	return authorization_digest(
		authorization,
		authorization->authorization_digest_hex);
}

int pqcp_adaptive_downgrade_evaluate(
	const struct pqcp_adaptive_profile *from,
	const struct pqcp_adaptive_profile *to,
	enum pqcp_adaptive_transition_reason reason,
	uint64_t now_ms,
	const struct pqcp_adaptive_policy *policy,
	const struct pqcp_adaptive_threat_assessment *threat,
	struct pqcp_adaptive_downgrade_authorization *authorization,
	struct pqcp_adaptive_downgrade_result *result)
{
	uint32_t from_strength;
	uint32_t to_strength;

	if (!pqcp_adaptive_internal_profile_valid(from) ||
	    !pqcp_adaptive_internal_profile_valid(to) ||
	    !reason_valid(reason) ||
	    pqcp_adaptive_policy_validate(policy) != 0 ||
	    result == NULL) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	result->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	pqcp_adaptive_internal_set_text(
		result->from_profile_id,
		sizeof(result->from_profile_id), from->profile_id);
	pqcp_adaptive_internal_set_text(
		result->to_profile_id,
		sizeof(result->to_profile_id), to->profile_id);
	from_strength =
		pqcp_adaptive_internal_profile_security_strength(from);
	to_strength =
		pqcp_adaptive_internal_profile_security_strength(to);
	result->downgrade = to_strength < from_strength;
	result->security_drop =
		from->security_level > to->security_level ?
		from->security_level - to->security_level : 0U;
	if (!result->downgrade) {
		result->status = PQCP_ADAPTIVE_STATUS_PASS;
		return result_digest(
			result, result->result_digest_hex);
	}
	result->authorization_required = true;
	if (!policy->allow_security_downgrade) {
		result->blocker_mask |=
			PQCP_ADAPTIVE_BLOCK_DOWNGRADE;
	}
	if (threat != NULL && threat->prohibit_downgrade) {
		result->blocker_mask |=
			PQCP_ADAPTIVE_BLOCK_DOWNGRADE;
	}
	if (authorization_valid(
		    authorization, from, to, reason,
		    now_ms, result->security_drop)) {
		result->authorization_valid = true;
		result->warning_mask |=
			PQCP_ADAPTIVE_WARNING_MANUAL_AUTHORIZATION;
		if (authorization != NULL) {
			authorization->consumed = true;
			result->consumed = true;
		}
	} else {
		result->blocker_mask |=
			PQCP_ADAPTIVE_BLOCK_DOWNGRADE;
	}
	if (result->blocker_mask != 0U) {
		result->status = PQCP_ADAPTIVE_STATUS_FAIL;
	} else {
		result->status = PQCP_ADAPTIVE_STATUS_WARN;
	}
	return result_digest(
		result, result->result_digest_hex);
}

int pqcp_adaptive_downgrade_emit(
	const struct pqcp_adaptive_downgrade_result *result)
{
	if (result == NULL ||
	    result->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	printk("PQCP_ADAPTIVE_DOWNGRADE schema=%u status=%s from=%s to=%s downgrade=%u security_drop=%u authorization_required=%u authorization_valid=%u consumed=%u blockers=0x%08x warnings=0x%08x digest=%s\n",
	       result->schema_version,
	       pqcp_adaptive_status_str(result->status),
	       result->from_profile_id,
	       result->to_profile_id,
	       result->downgrade ? 1U : 0U,
	       result->security_drop,
	       result->authorization_required ? 1U : 0U,
	       result->authorization_valid ? 1U : 0U,
	       result->consumed ? 1U : 0U,
	       result->blocker_mask,
	       result->warning_mask,
	       result->result_digest_hex);
	return 0;
}
