/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free multi-party authorization for high-risk fleet actions.
 *
 * Approval sessions bind policy and revocation epochs, authority-set
 * generation, action context, artifact identity, request nonce, deadline,
 * and an optional witnessed transparency checkpoint. Any bound state change
 * invalidates unfinished sessions fail-closed.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_APPROVAL_H_
#define PQCP_ZEPHYR_FLEET_APPROVAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/fleet_transparency.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_APPROVAL_SCHEMA_VERSION 1U
#define PQCP_FLEET_APPROVAL_ID_BYTES 32U
#define PQCP_FLEET_APPROVAL_NONCE_BYTES 32U
#define PQCP_FLEET_APPROVAL_MAX_CERTIFICATE_VOTES 32U

enum pqcp_fleet_approval_action {
	PQCP_FLEET_APPROVAL_ACTION_NONE = 0,
	PQCP_FLEET_APPROVAL_ACTION_POLICY_ACTIVATE,
	PQCP_FLEET_APPROVAL_ACTION_REVOCATION_PUBLISH,
	PQCP_FLEET_APPROVAL_ACTION_CREDENTIAL_ROTATE,
	PQCP_FLEET_APPROVAL_ACTION_UPDATE_AUTHORIZE,
	PQCP_FLEET_APPROVAL_ACTION_UPDATE_ACTIVATE,
	PQCP_FLEET_APPROVAL_ACTION_RECOVERY_ENTER,
	PQCP_FLEET_APPROVAL_ACTION_RECOVERY_EXIT,
	PQCP_FLEET_APPROVAL_ACTION_DECOMMISSION,
	PQCP_FLEET_APPROVAL_ACTION_TRUST_ANCHOR_ROTATE,
	PQCP_FLEET_APPROVAL_ACTION_LOG_KEY_ROTATE,
	PQCP_FLEET_APPROVAL_ACTION_CUSTOM,
	PQCP_FLEET_APPROVAL_ACTION_COUNT,
};

#define PQCP_FLEET_APPROVAL_ACTION_BIT(action) \
	(UINT64_C(1) << (uint32_t)(action))

enum pqcp_fleet_approval_role {
	PQCP_FLEET_APPROVAL_ROLE_SECURITY = (1U << 0),
	PQCP_FLEET_APPROVAL_ROLE_OPERATIONS = (1U << 1),
	PQCP_FLEET_APPROVAL_ROLE_COMPLIANCE = (1U << 2),
	PQCP_FLEET_APPROVAL_ROLE_VENDOR = (1U << 3),
	PQCP_FLEET_APPROVAL_ROLE_OWNER = (1U << 4),
	PQCP_FLEET_APPROVAL_ROLE_RECOVERY = (1U << 5),
};

enum pqcp_fleet_approval_authority_state {
	PQCP_FLEET_APPROVAL_AUTHORITY_EMPTY = 0,
	PQCP_FLEET_APPROVAL_AUTHORITY_ACTIVE,
	PQCP_FLEET_APPROVAL_AUTHORITY_SUSPENDED,
	PQCP_FLEET_APPROVAL_AUTHORITY_REVOKED,
};

enum pqcp_fleet_approval_decision {
	PQCP_FLEET_APPROVAL_DECISION_NONE = 0,
	PQCP_FLEET_APPROVAL_DECISION_APPROVE,
	PQCP_FLEET_APPROVAL_DECISION_DENY,
};

enum pqcp_fleet_approval_session_state {
	PQCP_FLEET_APPROVAL_SESSION_EMPTY = 0,
	PQCP_FLEET_APPROVAL_SESSION_OPEN,
	PQCP_FLEET_APPROVAL_SESSION_QUORUM,
	PQCP_FLEET_APPROVAL_SESSION_DENIED,
	PQCP_FLEET_APPROVAL_SESSION_CERTIFIED,
	PQCP_FLEET_APPROVAL_SESSION_CONSUMED,
	PQCP_FLEET_APPROVAL_SESSION_EXPIRED,
	PQCP_FLEET_APPROVAL_SESSION_CANCELLED,
};

struct pqcp_fleet_approval_authority {
	uint32_t schema_version;
	uint32_t generation;
	uint32_t roles;
	uint32_t weight;
	uint64_t action_mask;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint64_t revoked_at_ms;
	uint8_t authority_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES];
	enum pqcp_fleet_approval_authority_state state;
};

struct pqcp_fleet_approval_authority_set {
	uint32_t schema_version;
	uint64_t generation;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	struct pqcp_fleet_approval_authority *authorities;
	size_t capacity;
	struct pqcp_fleet_transparency_hash_ops hash;
	struct pqcp_fleet_transparency_signature_ops signatures;
	bool initialized;
};

struct pqcp_fleet_approval_policy {
	uint32_t schema_version;
	uint32_t generation;
	uint32_t minimum_approvals;
	uint32_t minimum_weight;
	uint32_t required_roles;
	uint32_t veto_roles;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t action_mask;
	uint64_t maximum_session_lifetime_ms;
	uint32_t minimum_witnesses;
	uint32_t minimum_witness_weight;
	uint32_t required_witness_roles;
	uint8_t policy_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	bool require_witnessed_checkpoint;
	bool enabled;
};

struct pqcp_fleet_approval_session_request {
	enum pqcp_fleet_approval_action action;
	uint64_t created_at_ms;
	uint64_t deadline_ms;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint8_t target_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t artifact_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t nonce[PQCP_FLEET_APPROVAL_NONCE_BYTES];
	const struct pqcp_fleet_transparency_checkpoint *checkpoint;
	const struct pqcp_fleet_transparency_witness_quorum *witness_quorum;
};

struct pqcp_fleet_approval_vote {
	uint32_t schema_version;
	uint32_t authority_generation;
	uint64_t issued_at_ms;
	uint64_t sequence;
	enum pqcp_fleet_approval_decision decision;
	uint8_t session_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t authority_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t transcript_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t *signature;
	size_t signature_capacity;
	size_t signature_length;
};

struct pqcp_fleet_approval_vote_record {
	uint32_t authority_generation;
	uint64_t issued_at_ms;
	uint64_t sequence;
	enum pqcp_fleet_approval_decision decision;
	uint8_t authority_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t transcript_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t signature_length;
	bool occupied;
};

struct pqcp_fleet_approval_session {
	uint32_t schema_version;
	uint32_t policy_generation;
	uint64_t authority_set_generation;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t created_at_ms;
	uint64_t deadline_ms;
	uint64_t checkpoint_tree_size;
	enum pqcp_fleet_approval_action action;
	enum pqcp_fleet_approval_session_state state;
	uint32_t approved_count;
	uint32_t approved_weight;
	uint32_t approved_roles;
	uint32_t denied_roles;
	uint8_t session_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t policy_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t target_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t artifact_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t nonce[PQCP_FLEET_APPROVAL_NONCE_BYTES];
	uint8_t checkpoint_log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES];
	uint8_t checkpoint_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	struct pqcp_fleet_approval_vote_record *votes;
	size_t vote_capacity;
	size_t vote_count;
	uint8_t *signature_arena;
	size_t signature_stride;
	bool checkpoint_bound;
};

struct pqcp_fleet_approval_certificate_vote {
	uint32_t authority_generation;
	uint64_t issued_at_ms;
	uint64_t sequence;
	uint8_t authority_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t vote_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t signature_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t signer_commitment[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t *signature;
	size_t signature_capacity;
	size_t signature_length;
};

struct pqcp_fleet_approval_certificate {
	uint32_t schema_version;
	uint32_t policy_generation;
	uint64_t authority_set_generation;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint64_t checkpoint_tree_size;
	enum pqcp_fleet_approval_action action;
	uint32_t approval_count;
	uint32_t approval_weight;
	uint32_t approval_roles;
	uint8_t certificate_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t session_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t policy_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t target_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint8_t artifact_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t checkpoint_log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES];
	uint8_t checkpoint_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	struct pqcp_fleet_approval_certificate_vote *votes;
	size_t vote_capacity;
	size_t vote_count;
	uint8_t *signature_arena;
	size_t signature_stride;
};

struct pqcp_fleet_approval_replay_entry {
	uint64_t consumed_at_ms;
	uint8_t certificate_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	bool occupied;
};

struct pqcp_fleet_approval_replay_guard {
	uint32_t schema_version;
	uint64_t generation;
	struct pqcp_fleet_approval_replay_entry *entries;
	size_t capacity;
	bool initialized;
};

int pqcp_fleet_approval_authority_set_init(
	struct pqcp_fleet_approval_authority_set *set,
	struct pqcp_fleet_approval_authority *authorities,
	size_t capacity,
	uint64_t policy_epoch,
	uint64_t revocation_epoch,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures);
int pqcp_fleet_approval_authority_upsert(
	struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_authority *authority);
int pqcp_fleet_approval_authority_revoke(
	struct pqcp_fleet_approval_authority_set *set,
	const uint8_t authority_id[PQCP_FLEET_APPROVAL_ID_BYTES],
	uint64_t revoked_at_ms);
int pqcp_fleet_approval_authority_set_advance_epochs(
	struct pqcp_fleet_approval_authority_set *set,
	uint64_t policy_epoch,
	uint64_t revocation_epoch);
int pqcp_fleet_approval_authority_set_verify(
	const struct pqcp_fleet_approval_authority_set *set);
int pqcp_fleet_approval_policy_validate(
	const struct pqcp_fleet_approval_policy *policy);

int pqcp_fleet_approval_session_open(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	const struct pqcp_fleet_approval_session_request *request,
	struct pqcp_fleet_approval_vote_record *vote_records,
	size_t vote_capacity,
	uint8_t *signature_arena,
	size_t signature_stride,
	struct pqcp_fleet_approval_session *session);
int pqcp_fleet_approval_session_refresh(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	uint64_t now_ms,
	struct pqcp_fleet_approval_session *session);
int pqcp_fleet_approval_session_cancel(
	struct pqcp_fleet_approval_session *session);
int pqcp_fleet_approval_vote_sign(
	const struct pqcp_fleet_approval_authority *authority,
	const struct pqcp_fleet_approval_session *session,
	enum pqcp_fleet_approval_decision decision,
	uint64_t issued_at_ms,
	uint64_t sequence,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures,
	uint8_t *signature_storage,
	size_t signature_capacity,
	struct pqcp_fleet_approval_vote *vote);
int pqcp_fleet_approval_vote_submit(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	const struct pqcp_fleet_approval_vote *vote,
	uint64_t now_ms,
	struct pqcp_fleet_approval_session *session);

int pqcp_fleet_approval_certificate_build(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	struct pqcp_fleet_approval_session *session,
	uint64_t now_ms,
	struct pqcp_fleet_approval_certificate_vote *certificate_votes,
	size_t vote_capacity,
	uint8_t *signature_arena,
	size_t signature_stride,
	struct pqcp_fleet_approval_certificate *certificate);
int pqcp_fleet_approval_certificate_verify(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	const struct pqcp_fleet_approval_session *session,
	const struct pqcp_fleet_approval_certificate *certificate,
	uint64_t now_ms);
int pqcp_fleet_approval_replay_guard_init(
	struct pqcp_fleet_approval_replay_guard *guard,
	struct pqcp_fleet_approval_replay_entry *entries,
	size_t capacity);
int pqcp_fleet_approval_certificate_consume(
	struct pqcp_fleet_approval_replay_guard *guard,
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	const struct pqcp_fleet_approval_certificate *certificate,
	uint64_t now_ms,
	struct pqcp_fleet_approval_session *session);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_APPROVAL_H_ */
