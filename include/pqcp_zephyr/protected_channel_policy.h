/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Protected-channel profile negotiation and downgrade policy.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_PROTECTED_CHANNEL_POLICY_H_
#define PQCP_ZEPHYR_PROTECTED_CHANNEL_POLICY_H_

#include <pqcp_zephyr/protected_channel.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_CHANNEL_POLICY_MAX_PROFILES 8U

enum pqcp_channel_policy_reason {
	PQCP_CHANNEL_POLICY_REASON_NONE = 0U,
	PQCP_CHANNEL_POLICY_REASON_NO_COMMON_PROFILE = (1U << 0),
	PQCP_CHANNEL_POLICY_REASON_SECURITY_LEVEL = (1U << 1),
	PQCP_CHANNEL_POLICY_REASON_KEM_NOT_COMPILED = (1U << 2),
	PQCP_CHANNEL_POLICY_REASON_SIGNATURE_NOT_COMPILED = (1U << 3),
	PQCP_CHANNEL_POLICY_REASON_MUTUAL_AUTH_REQUIRED = (1U << 4),
	PQCP_CHANNEL_POLICY_REASON_EVIDENCE_LEVEL = (1U << 5),
	PQCP_CHANNEL_POLICY_REASON_PROFILE_DISABLED = (1U << 6),
	PQCP_CHANNEL_POLICY_REASON_DOWNGRADE = (1U << 7),
	PQCP_CHANNEL_POLICY_REASON_RESOURCE_LIMIT = (1U << 8),
	PQCP_CHANNEL_POLICY_REASON_POLICY_HASH = (1U << 9),
};

struct pqcp_channel_profile_offer {
	uint32_t schema_version;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	uint32_t mlkem_level;
	uint32_t mldsa_level;
	uint32_t security_level;
	uint32_t evidence_score;
	uint32_t preference;
	uint64_t maximum_handshake_latency_us;
	uint64_t maximum_workspace_bytes;
	bool enabled;
	bool mutual_authentication;
};

struct pqcp_channel_policy {
	uint32_t schema_version;
	uint32_t minimum_security_level;
	uint32_t minimum_evidence_score;
	uint64_t maximum_handshake_latency_us;
	uint64_t maximum_workspace_bytes;
	bool require_mutual_authentication;
	bool forbid_downgrade;
	bool require_measured_profile;
	bool prefer_stronger_security;
	uint8_t policy_hash[PQCP_CHANNEL_HASH_BYTES];
};

struct pqcp_channel_negotiation {
	uint32_t schema_version;
	uint32_t reason_mask;
	uint32_t local_offer_count;
	uint32_t peer_offer_count;
	uint32_t common_offer_count;
	uint32_t selected_local_index;
	uint32_t selected_peer_index;
	struct pqcp_channel_profile_offer selected;
	uint8_t local_offer_hash[PQCP_CHANNEL_HASH_BYTES];
	uint8_t peer_offer_hash[PQCP_CHANNEL_HASH_BYTES];
	uint8_t negotiation_hash[PQCP_CHANNEL_HASH_BYTES];
	bool accepted;
	bool downgrade_detected;
};

int pqcp_channel_policy_default(
	struct pqcp_channel_policy *policy);
int pqcp_channel_policy_finalize(
	struct pqcp_channel_policy *policy);
int pqcp_channel_profile_offer_validate(
	const struct pqcp_channel_profile_offer *offer,
	const struct pqcp_runtime_capability *capability);
int pqcp_channel_negotiate(
	const struct pqcp_channel_policy *policy,
	const struct pqcp_runtime_capability *capability,
	const struct pqcp_channel_profile_offer *local_offers,
	size_t local_offer_count,
	const struct pqcp_channel_profile_offer *peer_offers,
	size_t peer_offer_count,
	const char *previous_profile,
	struct pqcp_channel_negotiation *negotiation);
int pqcp_channel_negotiation_verify(
	const struct pqcp_channel_policy *policy,
	const struct pqcp_channel_negotiation *negotiation);
int pqcp_channel_negotiation_apply(
	const struct pqcp_channel_negotiation *negotiation,
	enum pqcp_channel_role role,
	uint64_t session_id,
	uint32_t timeout_ms,
	const struct pqcp_runtime_key_handle *local_identity,
	const uint8_t *peer_identity_public,
	size_t peer_identity_public_length,
	struct pqcp_channel_config *config);
int pqcp_channel_negotiation_emit(
	const struct pqcp_channel_negotiation *negotiation);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_PROTECTED_CHANNEL_POLICY_H_ */
