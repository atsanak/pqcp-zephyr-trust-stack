/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deterministic protected-channel profile negotiation.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/protected_channel_policy.h>

#include "runtime_internal.h"

#define CHANNEL_POLICY_DOMAIN UINT64_C(0x5051435043504f31)
#define CHANNEL_OFFER_DOMAIN UINT64_C(0x50514350434f4631)
#define CHANNEL_NEGOTIATION_DOMAIN UINT64_C(0x50514350434e4731)

static bool policy_fields_valid(
	const struct pqcp_channel_policy *policy)
{
	return policy != NULL &&
	       policy->schema_version == PQCP_CHANNEL_SCHEMA_VERSION &&
	       policy->minimum_security_level >= 1U &&
	       policy->minimum_security_level <= 5U &&
	       policy->minimum_evidence_score <= 100U &&
	       policy->maximum_handshake_latency_us != 0U &&
	       policy->maximum_workspace_bytes != 0U;
}

static int policy_hash(
	const struct pqcp_channel_policy *policy,
	uint8_t output[PQCP_CHANNEL_HASH_BYTES])
{
	uint8_t buffer[64];
	size_t offset = 0U;

	memset(buffer, 0, sizeof(buffer));
	pqcp_runtime_internal_write_u64(
		buffer + offset, CHANNEL_POLICY_DOMAIN);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, policy->minimum_security_level);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, policy->minimum_evidence_score);
	offset += 4U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, policy->maximum_handshake_latency_us);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, policy->maximum_workspace_bytes);
	offset += 8U;
	buffer[offset++] =
		policy->require_mutual_authentication ? 1U : 0U;
	buffer[offset++] = policy->forbid_downgrade ? 1U : 0U;
	buffer[offset++] = policy->require_measured_profile ? 1U : 0U;
	buffer[offset++] = policy->prefer_stronger_security ? 1U : 0U;
	return pqcp_runtime_internal_sha256(buffer, offset, output);
}

int pqcp_channel_policy_default(
	struct pqcp_channel_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	*policy = (struct pqcp_channel_policy) {
		.schema_version = PQCP_CHANNEL_SCHEMA_VERSION,
		.minimum_security_level = 3U,
		.minimum_evidence_score = 70U,
		.maximum_handshake_latency_us = 10000000U,
		.maximum_workspace_bytes = CONFIG_PQCP_RUNTIME_WORKSPACE_BYTES,
		.require_mutual_authentication = false,
		.forbid_downgrade = true,
		.require_measured_profile = false,
		.prefer_stronger_security = false,
	};
	return pqcp_channel_policy_finalize(policy);
}

int pqcp_channel_policy_finalize(
	struct pqcp_channel_policy *policy)
{
	if (!policy_fields_valid(policy)) {
		return -EINVAL;
	}
	return policy_hash(policy, policy->policy_hash);
}

static uint32_t mlkem_mask_for_level(uint32_t level)
{
	switch (level) {
	case 512U:
		return PQCP_BUILD_MLKEM_LEVEL_512;
	case 768U:
		return PQCP_BUILD_MLKEM_LEVEL_768;
	case 1024U:
		return PQCP_BUILD_MLKEM_LEVEL_1024;
	default:
		return 0U;
	}
}

static uint32_t mldsa_mask_for_level(uint32_t level)
{
	switch (level) {
	case 44U:
		return PQCP_BUILD_MLDSA_LEVEL_44;
	case 65U:
		return PQCP_BUILD_MLDSA_LEVEL_65;
	case 87U:
		return PQCP_BUILD_MLDSA_LEVEL_87;
	default:
		return 0U;
	}
}

int pqcp_channel_profile_offer_validate(
	const struct pqcp_channel_profile_offer *offer,
	const struct pqcp_runtime_capability *capability)
{
	if (offer == NULL || capability == NULL ||
	    offer->schema_version != PQCP_CHANNEL_SCHEMA_VERSION ||
	    !pqcp_runtime_internal_text_valid(
		    offer->profile_id, sizeof(offer->profile_id)) ||
	    offer->security_level < 1U ||
	    offer->security_level > 5U ||
	    offer->evidence_score > 100U ||
	    offer->maximum_handshake_latency_us == 0U ||
	    offer->maximum_workspace_bytes == 0U ||
	    mlkem_mask_for_level(offer->mlkem_level) == 0U ||
	    mldsa_mask_for_level(offer->mldsa_level) == 0U) {
		return -EINVAL;
	}
	if ((capability->mlkem_level_mask &
	     mlkem_mask_for_level(offer->mlkem_level)) == 0U ||
	    (capability->mldsa_level_mask &
	     mldsa_mask_for_level(offer->mldsa_level)) == 0U) {
		return -ENOTSUP;
	}
	return 0;
}

static bool offer_equivalent(
	const struct pqcp_channel_profile_offer *first,
	const struct pqcp_channel_profile_offer *second)
{
	return first->mlkem_level == second->mlkem_level &&
	       first->mldsa_level == second->mldsa_level &&
	       first->security_level == second->security_level &&
	       strcmp(first->profile_id, second->profile_id) == 0;
}

static uint64_t offer_score(
	const struct pqcp_channel_policy *policy,
	const struct pqcp_channel_profile_offer *offer)
{
	uint64_t score = 0U;

	score += (uint64_t)offer->evidence_score * 100000U;
	score += (uint64_t)offer->preference * 1000U;
	if (policy->prefer_stronger_security) {
		score += (uint64_t)offer->security_level * 1000000U;
	} else {
		score +=
			(uint64_t)(6U - offer->security_level) * 1000U;
	}
	if (offer->maximum_handshake_latency_us != 0U) {
		score += 1000000000U /
			offer->maximum_handshake_latency_us;
	}
	if (offer->maximum_workspace_bytes != 0U) {
		score += 1000000000U /
			offer->maximum_workspace_bytes;
	}
	return score;
}

static uint32_t offer_reasons(
	const struct pqcp_channel_policy *policy,
	const struct pqcp_runtime_capability *capability,
	const struct pqcp_channel_profile_offer *offer)
{
	uint32_t reasons = 0U;

	if (!offer->enabled) {
		reasons |= PQCP_CHANNEL_POLICY_REASON_PROFILE_DISABLED;
	}
	if (offer->security_level < policy->minimum_security_level) {
		reasons |= PQCP_CHANNEL_POLICY_REASON_SECURITY_LEVEL;
	}
	if ((capability->mlkem_level_mask &
	     mlkem_mask_for_level(offer->mlkem_level)) == 0U) {
		reasons |= PQCP_CHANNEL_POLICY_REASON_KEM_NOT_COMPILED;
	}
	if ((capability->mldsa_level_mask &
	     mldsa_mask_for_level(offer->mldsa_level)) == 0U) {
		reasons |=
			PQCP_CHANNEL_POLICY_REASON_SIGNATURE_NOT_COMPILED;
	}
	if (policy->require_mutual_authentication &&
	    !offer->mutual_authentication) {
		reasons |=
			PQCP_CHANNEL_POLICY_REASON_MUTUAL_AUTH_REQUIRED;
	}
	if (offer->evidence_score <
	    policy->minimum_evidence_score) {
		reasons |= PQCP_CHANNEL_POLICY_REASON_EVIDENCE_LEVEL;
	}
	if (offer->maximum_handshake_latency_us >
		    policy->maximum_handshake_latency_us ||
	    offer->maximum_workspace_bytes >
		    policy->maximum_workspace_bytes) {
		reasons |= PQCP_CHANNEL_POLICY_REASON_RESOURCE_LIMIT;
	}
	return reasons;
}

static int offers_hash(
	const struct pqcp_channel_profile_offer *offers,
	size_t count,
	uint8_t output[PQCP_CHANNEL_HASH_BYTES])
{
	uint8_t buffer[32U +
		       PQCP_CHANNEL_POLICY_MAX_PROFILES * 96U];
	size_t offset = 0U;

	if (offers == NULL || count == 0U ||
	    count > PQCP_CHANNEL_POLICY_MAX_PROFILES) {
		return -EINVAL;
	}
	memset(buffer, 0, sizeof(buffer));
	pqcp_runtime_internal_write_u64(
		buffer + offset, CHANNEL_OFFER_DOMAIN);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, (uint32_t)count);
	offset += 4U;
	for (size_t index = 0U; index < count; ++index) {
		const struct pqcp_channel_profile_offer *offer =
			&offers[index];
		size_t length = strnlen(
			offer->profile_id,
			sizeof(offer->profile_id));

		pqcp_runtime_internal_write_u32(
			buffer + offset, offer->mlkem_level);
		offset += 4U;
		pqcp_runtime_internal_write_u32(
			buffer + offset, offer->mldsa_level);
		offset += 4U;
		pqcp_runtime_internal_write_u32(
			buffer + offset, offer->security_level);
		offset += 4U;
		pqcp_runtime_internal_write_u32(
			buffer + offset, offer->evidence_score);
		offset += 4U;
		pqcp_runtime_internal_write_u32(
			buffer + offset, offer->preference);
		offset += 4U;
		pqcp_runtime_internal_write_u64(
			buffer + offset,
			offer->maximum_handshake_latency_us);
		offset += 8U;
		pqcp_runtime_internal_write_u64(
			buffer + offset,
			offer->maximum_workspace_bytes);
		offset += 8U;
		buffer[offset++] = offer->enabled ? 1U : 0U;
		buffer[offset++] =
			offer->mutual_authentication ? 1U : 0U;
		memcpy(buffer + offset, offer->profile_id, length);
		offset += length;
		buffer[offset++] = 0U;
	}
	return pqcp_runtime_internal_sha256(buffer, offset, output);
}

static int negotiation_hash(
	const struct pqcp_channel_policy *policy,
	const struct pqcp_channel_negotiation *negotiation,
	uint8_t output[PQCP_CHANNEL_HASH_BYTES])
{
	uint8_t buffer[256];
	size_t offset = 0U;
	size_t profile_length = strnlen(
		negotiation->selected.profile_id,
		sizeof(negotiation->selected.profile_id));

	memset(buffer, 0, sizeof(buffer));
	pqcp_runtime_internal_write_u64(
		buffer + offset, CHANNEL_NEGOTIATION_DOMAIN);
	offset += 8U;
	memcpy(buffer + offset, policy->policy_hash,
	       sizeof(policy->policy_hash));
	offset += sizeof(policy->policy_hash);
	memcpy(buffer + offset, negotiation->local_offer_hash,
	       sizeof(negotiation->local_offer_hash));
	offset += sizeof(negotiation->local_offer_hash);
	memcpy(buffer + offset, negotiation->peer_offer_hash,
	       sizeof(negotiation->peer_offer_hash));
	offset += sizeof(negotiation->peer_offer_hash);
	pqcp_runtime_internal_write_u32(
		buffer + offset, negotiation->reason_mask);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, negotiation->selected_local_index);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, negotiation->selected_peer_index);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, negotiation->selected.mlkem_level);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, negotiation->selected.mldsa_level);
	offset += 4U;
	buffer[offset++] = negotiation->accepted ? 1U : 0U;
	buffer[offset++] =
		negotiation->downgrade_detected ? 1U : 0U;
	memcpy(buffer + offset,
	       negotiation->selected.profile_id, profile_length);
	offset += profile_length;
	return pqcp_runtime_internal_sha256(buffer, offset, output);
}

int pqcp_channel_negotiate(
	const struct pqcp_channel_policy *policy,
	const struct pqcp_runtime_capability *capability,
	const struct pqcp_channel_profile_offer *local_offers,
	size_t local_offer_count,
	const struct pqcp_channel_profile_offer *peer_offers,
	size_t peer_offer_count,
	const char *previous_profile,
	struct pqcp_channel_negotiation *negotiation)
{
	uint8_t expected_policy_hash[PQCP_CHANNEL_HASH_BYTES];
	uint64_t best_score = 0U;
	bool found = false;

	if (!policy_fields_valid(policy) ||
	    capability == NULL || local_offers == NULL ||
	    peer_offers == NULL || negotiation == NULL ||
	    local_offer_count == 0U || peer_offer_count == 0U ||
	    local_offer_count > PQCP_CHANNEL_POLICY_MAX_PROFILES ||
	    peer_offer_count > PQCP_CHANNEL_POLICY_MAX_PROFILES ||
	    policy_hash(policy, expected_policy_hash) != 0 ||
	    memcmp(expected_policy_hash, policy->policy_hash,
		   sizeof(expected_policy_hash)) != 0) {
		return -EINVAL;
	}
	memset(negotiation, 0, sizeof(*negotiation));
	negotiation->schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	negotiation->local_offer_count =
		(uint32_t)local_offer_count;
	negotiation->peer_offer_count =
		(uint32_t)peer_offer_count;
	negotiation->selected_local_index = UINT32_MAX;
	negotiation->selected_peer_index = UINT32_MAX;
	if (offers_hash(local_offers, local_offer_count,
			negotiation->local_offer_hash) != 0 ||
	    offers_hash(peer_offers, peer_offer_count,
			negotiation->peer_offer_hash) != 0) {
		return -EINVAL;
	}
	for (size_t local = 0U; local < local_offer_count; ++local) {
		if (pqcp_channel_profile_offer_validate(
			    &local_offers[local], capability) != 0) {
			continue;
		}
		for (size_t peer = 0U; peer < peer_offer_count; ++peer) {
			uint32_t reasons;
			uint64_t score;

			if (!offer_equivalent(
				    &local_offers[local],
				    &peer_offers[peer])) {
				continue;
			}
			negotiation->common_offer_count++;
			reasons = offer_reasons(
				policy, capability,
				&local_offers[local]);
			reasons |= offer_reasons(
				policy, capability,
				&peer_offers[peer]);
			if (reasons != 0U) {
				negotiation->reason_mask |= reasons;
				continue;
			}
			score = offer_score(
				policy, &local_offers[local]);
			if (!found || score > best_score) {
				found = true;
				best_score = score;
				negotiation->selected =
					local_offers[local];
				negotiation->selected_local_index =
					(uint32_t)local;
				negotiation->selected_peer_index =
					(uint32_t)peer;
			}
		}
	}
	if (!found) {
		negotiation->reason_mask |=
			PQCP_CHANNEL_POLICY_REASON_NO_COMMON_PROFILE;
	} else if (policy->forbid_downgrade &&
		   previous_profile != NULL &&
		   previous_profile[0] != '\0' &&
		   strcmp(previous_profile,
			  negotiation->selected.profile_id) != 0) {
		const struct pqcp_channel_profile_offer *previous = NULL;

		for (size_t index = 0U;
		     index < local_offer_count; ++index) {
			if (strcmp(local_offers[index].profile_id,
				   previous_profile) == 0) {
				previous = &local_offers[index];
				break;
			}
		}
		if (previous != NULL &&
		    negotiation->selected.security_level <
			    previous->security_level) {
			negotiation->downgrade_detected = true;
			negotiation->reason_mask |=
				PQCP_CHANNEL_POLICY_REASON_DOWNGRADE;
		}
	}
	negotiation->accepted =
		found && !negotiation->downgrade_detected;
	return negotiation_hash(
		policy, negotiation,
		negotiation->negotiation_hash);
}

int pqcp_channel_negotiation_verify(
	const struct pqcp_channel_policy *policy,
	const struct pqcp_channel_negotiation *negotiation)
{
	uint8_t expected_policy_hash[PQCP_CHANNEL_HASH_BYTES];
	uint8_t expected_negotiation_hash[PQCP_CHANNEL_HASH_BYTES];

	if (!policy_fields_valid(policy) || negotiation == NULL ||
	    negotiation->schema_version !=
		    PQCP_CHANNEL_SCHEMA_VERSION ||
	    policy_hash(policy, expected_policy_hash) != 0 ||
	    memcmp(expected_policy_hash, policy->policy_hash,
		   sizeof(expected_policy_hash)) != 0 ||
	    negotiation_hash(
		    policy, negotiation,
		    expected_negotiation_hash) != 0 ||
	    memcmp(expected_negotiation_hash,
		   negotiation->negotiation_hash,
		   sizeof(expected_negotiation_hash)) != 0) {
		return -EBADMSG;
	}
	if (negotiation->accepted &&
	    (negotiation->common_offer_count == 0U ||
	     negotiation->selected_local_index == UINT32_MAX ||
	     negotiation->selected_peer_index == UINT32_MAX ||
	     negotiation->downgrade_detected ||
	     !pqcp_runtime_internal_text_valid(
		     negotiation->selected.profile_id,
		     sizeof(negotiation->selected.profile_id)))) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_channel_negotiation_apply(
	const struct pqcp_channel_negotiation *negotiation,
	enum pqcp_channel_role role,
	uint64_t session_id,
	uint32_t timeout_ms,
	const struct pqcp_runtime_key_handle *local_identity,
	const uint8_t *peer_identity_public,
	size_t peer_identity_public_length,
	struct pqcp_channel_config *config)
{
	if (negotiation == NULL || !negotiation->accepted ||
	    config == NULL || session_id == 0U ||
	    timeout_ms == 0U ||
	    (role != PQCP_CHANNEL_ROLE_CLIENT &&
	     role != PQCP_CHANNEL_ROLE_SERVER) ||
	    local_identity == NULL ||
	    !pqcp_runtime_key_handle_is_valid(local_identity) ||
	    peer_identity_public == NULL ||
	    peer_identity_public_length == 0U ||
	    peer_identity_public_length >
		    sizeof(config->peer_identity_public)) {
		return -EINVAL;
	}
	memset(config, 0, sizeof(*config));
	config->schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	config->role = role;
	config->session_id = session_id;
	config->mlkem_level = negotiation->selected.mlkem_level;
	config->mldsa_level = negotiation->selected.mldsa_level;
	config->timeout_ms = timeout_ms;
	config->max_payload_bytes = PQCP_CHANNEL_MAX_PAYLOAD_BYTES;
	config->local_identity = *local_identity;
	memcpy(config->peer_identity_public,
	       peer_identity_public,
	       peer_identity_public_length);
	config->peer_identity_public_length =
		peer_identity_public_length;
	config->require_mutual_authentication =
		negotiation->selected.mutual_authentication;
	return pqcp_runtime_internal_copy_text(
		config->profile_id, sizeof(config->profile_id),
		negotiation->selected.profile_id);
}

int pqcp_channel_negotiation_emit(
	const struct pqcp_channel_negotiation *negotiation)
{
	char digest_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];

	if (negotiation == NULL ||
	    pqcp_runtime_internal_hex(
		    negotiation->negotiation_hash,
		    sizeof(negotiation->negotiation_hash),
		    digest_hex, sizeof(digest_hex)) != 0) {
		return -EINVAL;
	}
	printk("PQCP_CHANNEL_NEGOTIATION status=%s profile=%s mlkem=%u mldsa=%u security=%u evidence=%u common=%u reasons=0x%08x downgrade=%u digest=%s\n",
	       negotiation->accepted ? "PASS" : "FAIL",
	       negotiation->accepted ?
		       negotiation->selected.profile_id : "none",
	       negotiation->selected.mlkem_level,
	       negotiation->selected.mldsa_level,
	       negotiation->selected.security_level,
	       negotiation->selected.evidence_score,
	       negotiation->common_offer_count,
	       negotiation->reason_mask,
	       negotiation->downgrade_detected ? 1U : 0U,
	       digest_hex);
	return 0;
}
