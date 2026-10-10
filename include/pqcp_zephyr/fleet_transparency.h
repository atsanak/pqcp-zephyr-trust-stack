/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Host-portable transparency primitives for fleet security artifacts.
 *
 * The Merkle construction follows the domain separation and tree shape from
 * RFC 9162. Storage, hashing, signing, and persistence are supplied by the
 * caller so the implementation can be used by firmware and hosted tools
 * without a second protocol authority or a dynamic allocator.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_TRANSPARENCY_H_
#define PQCP_ZEPHYR_FLEET_TRANSPARENCY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION 1U
#define PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES 32U
#define PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES 32U
#define PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES 32U
#define PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES 32U
#define PQCP_FLEET_TRANSPARENCY_MAX_LEVELS 64U
#define PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES 65U

/**
 * One immutable byte range supplied to a hashing or signing callback.
 *
 * A NULL data pointer is valid only when length is zero.
 */
struct pqcp_fleet_transparency_part {
	const uint8_t *data;
	size_t length;
};

/**
 * Hash provider used by every transparency primitive.
 *
 * The callback computes one SHA-256-compatible 32-byte digest over the exact
 * concatenation of parts[0] through parts[part_count - 1]. A zero-part call
 * hashes the empty string. The callback must not retain any input pointer.
 */
struct pqcp_fleet_transparency_hash_ops {
	void *context;
	int (*digest)(
		void *context,
		const struct pqcp_fleet_transparency_part *parts,
		size_t part_count,
		uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES]);
};

/**
 * Detached signature provider.
 *
 * Implementations typically dispatch by key_id to ML-DSA-65, but the core
 * intentionally does not own keys or mandate a provider. Both callbacks act
 * on the exact concatenation of the supplied semantic transcript parts.
 */
struct pqcp_fleet_transparency_signature_ops {
	void *context;
	int (*sign)(
		void *context,
		const uint8_t key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES],
		const struct pqcp_fleet_transparency_part *parts,
		size_t part_count,
		uint8_t *signature,
		size_t signature_capacity,
		size_t *signature_length);
	int (*verify)(
		void *context,
		const uint8_t key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES],
		const struct pqcp_fleet_transparency_part *parts,
		size_t part_count,
		const uint8_t *signature,
		size_t signature_length);
};

/**
 * Caller-owned scratch area for transactional frontier updates.
 *
 * A workspace may be reused between calls after each call returns. It must
 * not be shared concurrently by multiple operations.
 */
struct pqcp_fleet_transparency_workspace {
	uint8_t frontier[PQCP_FLEET_TRANSPARENCY_MAX_LEVELS]
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint64_t frontier_mask;
	uint8_t root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t carry[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
};

/**
 * Compact state summary suitable for persistence and checkpoint binding.
 */
struct pqcp_fleet_transparency_snapshot {
	uint32_t schema_version;
	uint64_t tree_size;
	uint64_t generation;
	uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES];
	uint8_t root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
};

/**
 * Bounded append-only transparency log.
 *
 * leaf_hashes points to capacity caller-owned 32-byte slots. The complete
 * leaf-hash history is retained so inclusion and consistency proofs can be
 * produced without dynamic allocation. The compact frontier keeps append
 * cost logarithmic in tree size.
 */
struct pqcp_fleet_transparency_log {
	uint32_t schema_version;
	uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES];
	uint8_t (*leaf_hashes)[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t capacity;
	uint64_t tree_size;
	uint64_t generation;
	uint8_t frontier[PQCP_FLEET_TRANSPARENCY_MAX_LEVELS]
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint64_t frontier_mask;
	uint8_t root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	struct pqcp_fleet_transparency_hash_ops hash;
	bool initialized;
};

/**
 * RFC 9162-style Merkle inclusion proof.
 *
 * nodes are ordered from the leaf level toward the root.
 */
struct pqcp_fleet_transparency_inclusion_proof {
	uint32_t schema_version;
	uint64_t tree_size;
	uint64_t leaf_index;
	uint8_t leaf_hash[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t nodes[PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES]
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t node_count;
};

/**
 * RFC 9162-style proof that a newer tree extends an older tree.
 */
struct pqcp_fleet_transparency_consistency_proof {
	uint32_t schema_version;
	uint64_t old_tree_size;
	uint64_t new_tree_size;
	uint8_t old_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t new_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t nodes[PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES]
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t node_count;
};

/**
 * Signed semantic checkpoint for one immutable log history.
 *
 * signature points to caller-owned storage. Copying this structure does not
 * copy signature bytes.
 */
struct pqcp_fleet_transparency_checkpoint {
	uint32_t schema_version;
	uint64_t tree_size;
	uint64_t timestamp_ms;
	uint64_t sequence;
	uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES];
	uint8_t root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t signer_key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES];
	uint8_t transcript_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t *signature;
	size_t signature_capacity;
	size_t signature_length;
};

/**
 * Persistence callbacks for the last accepted checkpoint.
 *
 * load writes checkpoint fields and signature bytes into the supplied
 * storage. store must durably commit the complete checkpoint before return.
 */
struct pqcp_fleet_transparency_checkpoint_store_ops {
	void *context;
	int (*load)(
		void *context,
		struct pqcp_fleet_transparency_checkpoint *checkpoint,
		uint8_t *signature_storage,
		size_t signature_capacity);
	int (*store)(
		void *context,
		const struct pqcp_fleet_transparency_checkpoint *checkpoint);
};

/**
 * Monotonic checkpoint guard.
 */
struct pqcp_fleet_transparency_checkpoint_guard {
	uint32_t schema_version;
	uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES];
	uint8_t trusted_signer_key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES];
	struct pqcp_fleet_transparency_checkpoint latest;
	uint8_t *signature_storage;
	size_t signature_capacity;
	struct pqcp_fleet_transparency_hash_ops hash;
	struct pqcp_fleet_transparency_signature_ops signatures;
	struct pqcp_fleet_transparency_checkpoint_store_ops persistence;
	bool has_checkpoint;
	bool initialized;
};

enum pqcp_fleet_transparency_witness_state {
	PQCP_FLEET_TRANSPARENCY_WITNESS_EMPTY = 0,
	PQCP_FLEET_TRANSPARENCY_WITNESS_ACTIVE,
	PQCP_FLEET_TRANSPARENCY_WITNESS_SUSPENDED,
	PQCP_FLEET_TRANSPARENCY_WITNESS_REVOKED,
};

enum pqcp_fleet_transparency_witness_role {
	PQCP_FLEET_TRANSPARENCY_WITNESS_OPERATOR = (1U << 0),
	PQCP_FLEET_TRANSPARENCY_WITNESS_AUDITOR = (1U << 1),
	PQCP_FLEET_TRANSPARENCY_WITNESS_VENDOR = (1U << 2),
	PQCP_FLEET_TRANSPARENCY_WITNESS_REGULATOR = (1U << 3),
	PQCP_FLEET_TRANSPARENCY_WITNESS_DEVICE = (1U << 4),
};

struct pqcp_fleet_transparency_witness_authority {
	uint32_t schema_version;
	uint32_t generation;
	uint32_t roles;
	uint32_t weight;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint64_t revoked_at_ms;
	uint8_t witness_id[PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES];
	uint8_t key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES];
	enum pqcp_fleet_transparency_witness_state state;
};

/**
 * A witness signature over one verified checkpoint.
 */
struct pqcp_fleet_transparency_witness_statement {
	uint32_t schema_version;
	uint32_t authority_generation;
	uint64_t observed_at_ms;
	uint64_t sequence;
	uint8_t witness_id[PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES];
	uint8_t checkpoint_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t transcript_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t *signature;
	size_t signature_capacity;
	size_t signature_length;
};

struct pqcp_fleet_transparency_witness_record {
	struct pqcp_fleet_transparency_witness_authority authority;
	uint64_t latest_tree_size;
	uint64_t latest_observed_at_ms;
	uint64_t latest_sequence;
	uint8_t latest_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t latest_checkpoint_digest
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t latest_statement_digest
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t signature_length;
	bool has_observation;
};

struct pqcp_fleet_transparency_witness_registry {
	uint32_t schema_version;
	uint64_t generation;
	uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES];
	uint8_t trusted_log_key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES];
	struct pqcp_fleet_transparency_witness_record *records;
	size_t capacity;
	uint8_t *signature_arena;
	size_t signature_stride;
	struct pqcp_fleet_transparency_hash_ops hash;
	struct pqcp_fleet_transparency_signature_ops signatures;
	bool initialized;
};

struct pqcp_fleet_transparency_witness_policy {
	uint32_t minimum_witnesses;
	uint32_t minimum_weight;
	uint32_t required_roles;
	uint64_t maximum_observation_age_ms;
};

struct pqcp_fleet_transparency_witness_quorum {
	uint32_t witness_count;
	uint32_t total_weight;
	uint32_t observed_roles;
	uint8_t checkpoint_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	bool count_met;
	bool weight_met;
	bool roles_met;
	bool reached;
};

enum pqcp_fleet_transparency_evidence_kind {
	PQCP_FLEET_TRANSPARENCY_EVIDENCE_NONE = 0,
	PQCP_FLEET_TRANSPARENCY_EVIDENCE_ROLLBACK,
	PQCP_FLEET_TRANSPARENCY_EVIDENCE_EQUIVOCATION,
	PQCP_FLEET_TRANSPARENCY_EVIDENCE_INCONSISTENT_GROWTH,
	PQCP_FLEET_TRANSPARENCY_EVIDENCE_REPLAY,
};

/**
 * Compact, persistable evidence of a history violation.
 */
struct pqcp_fleet_transparency_evidence {
	uint32_t schema_version;
	enum pqcp_fleet_transparency_evidence_kind kind;
	uint64_t detected_at_ms;
	uint64_t first_tree_size;
	uint64_t second_tree_size;
	uint64_t first_sequence;
	uint64_t second_sequence;
	uint8_t participant_id
		[PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES];
	uint8_t first_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t second_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t first_statement_digest
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t second_statement_digest
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t evidence_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
};

enum pqcp_fleet_transparency_gossip_peer_state {
	PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_EMPTY = 0,
	PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_ACTIVE,
	PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_SUSPENDED,
	PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_REVOKED,
};

struct pqcp_fleet_transparency_gossip_peer {
	uint32_t schema_version;
	uint32_t generation;
	uint64_t not_before_ms;
	uint64_t expires_at_ms;
	uint64_t latest_tree_size;
	uint64_t latest_sequence;
	uint64_t latest_received_at_ms;
	uint8_t peer_id[PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES];
	uint8_t key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES];
	uint8_t latest_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t latest_checkpoint_digest
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t latest_message_digest
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	enum pqcp_fleet_transparency_gossip_peer_state state;
	bool has_summary;
};

struct pqcp_fleet_transparency_gossip_message {
	uint32_t schema_version;
	uint32_t peer_generation;
	uint64_t tree_size;
	uint64_t sent_at_ms;
	uint64_t sequence;
	uint8_t peer_id[PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES];
	uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES];
	uint8_t root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t checkpoint_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t transcript_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t *signature;
	size_t signature_capacity;
	size_t signature_length;
};

struct pqcp_fleet_transparency_gossip_monitor {
	uint32_t schema_version;
	uint64_t generation;
	uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES];
	struct pqcp_fleet_transparency_gossip_peer *peers;
	size_t capacity;
	struct pqcp_fleet_transparency_hash_ops hash;
	struct pqcp_fleet_transparency_signature_ops signatures;
	bool initialized;
};

/**
 * Compute HASH("") for the configured digest provider.
 */
int pqcp_fleet_transparency_empty_root(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES]);

/**
 * Compute HASH(0x00 || leaf), as required by RFC 9162.
 */
int pqcp_fleet_transparency_leaf_hash(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const uint8_t *leaf,
	size_t leaf_length,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES]);

/**
 * Compute HASH(0x01 || left || right), as required by RFC 9162.
 */
int pqcp_fleet_transparency_node_hash(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const uint8_t left[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES]);

/**
 * Compute the canonical RFC 9162 root over already domain-separated leaves.
 */
int pqcp_fleet_transparency_root_from_hashes(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const uint8_t (*leaf_hashes)
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	size_t leaf_count,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES]);

/**
 * Initialize an empty bounded log.
 */
int pqcp_fleet_transparency_log_init(
	struct pqcp_fleet_transparency_log *log,
	const uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES],
	uint8_t (*leaf_hashes)[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	size_t capacity,
	const struct pqcp_fleet_transparency_hash_ops *hash);

/**
 * Restore a log from leaf hashes already present in its caller-owned storage.
 *
 * The function rebuilds the frontier and root transactionally. No state is
 * committed when a hash callback fails or the supplied count is invalid.
 */
int pqcp_fleet_transparency_log_restore(
	struct pqcp_fleet_transparency_log *log,
	size_t leaf_count,
	uint64_t generation,
	struct pqcp_fleet_transparency_workspace *workspace);

/**
 * Append one exact statement representation to the log.
 *
 * On success leaf_index receives the immutable zero-based index. The append
 * is transactional with respect to callback failures.
 */
int pqcp_fleet_transparency_log_append(
	struct pqcp_fleet_transparency_log *log,
	const uint8_t *statement,
	size_t statement_length,
	struct pqcp_fleet_transparency_workspace *workspace,
	uint64_t *leaf_index);

/**
 * Return a stable state summary.
 */
int pqcp_fleet_transparency_log_snapshot(
	const struct pqcp_fleet_transparency_log *log,
	struct pqcp_fleet_transparency_snapshot *snapshot);

/**
 * Rebuild and audit all compact log state against retained leaves.
 */
int pqcp_fleet_transparency_log_verify(
	const struct pqcp_fleet_transparency_log *log,
	struct pqcp_fleet_transparency_workspace *workspace);

/**
 * Generate and verify Merkle inclusion proofs.
 */
int pqcp_fleet_transparency_inclusion_proof_generate(
	const struct pqcp_fleet_transparency_log *log,
	uint64_t leaf_index,
	uint64_t tree_size,
	struct pqcp_fleet_transparency_inclusion_proof *proof);
int pqcp_fleet_transparency_inclusion_proof_verify(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_inclusion_proof *proof);

/**
 * Generate and verify append-only consistency proofs.
 */
int pqcp_fleet_transparency_consistency_proof_generate(
	const struct pqcp_fleet_transparency_log *log,
	uint64_t old_tree_size,
	uint64_t new_tree_size,
	struct pqcp_fleet_transparency_consistency_proof *proof);
int pqcp_fleet_transparency_consistency_proof_verify(
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_consistency_proof *proof);

/**
 * Create, verify, copy, and monotonically persist signed checkpoints.
 */
int pqcp_fleet_transparency_checkpoint_sign(
	const struct pqcp_fleet_transparency_snapshot *snapshot,
	uint64_t timestamp_ms,
	uint64_t sequence,
	const uint8_t signer_key_id
		[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES],
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures,
	uint8_t *signature_storage,
	size_t signature_capacity,
	struct pqcp_fleet_transparency_checkpoint *checkpoint);
int pqcp_fleet_transparency_checkpoint_verify(
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures);
int pqcp_fleet_transparency_checkpoint_guard_init(
	struct pqcp_fleet_transparency_checkpoint_guard *guard,
	const uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES],
	const uint8_t trusted_signer_key_id
		[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES],
	uint8_t *signature_storage,
	size_t signature_capacity,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures,
	const struct pqcp_fleet_transparency_checkpoint_store_ops *persistence);
int pqcp_fleet_transparency_checkpoint_guard_restore(
	struct pqcp_fleet_transparency_checkpoint_guard *guard);
int pqcp_fleet_transparency_checkpoint_guard_accept(
	struct pqcp_fleet_transparency_checkpoint_guard *guard,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	const struct pqcp_fleet_transparency_consistency_proof *consistency);

/**
 * Manage independent witnesses and evaluate checkpoint quorum.
 */
int pqcp_fleet_transparency_witness_registry_init(
	struct pqcp_fleet_transparency_witness_registry *registry,
	const uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES],
	const uint8_t trusted_log_key_id
		[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES],
	struct pqcp_fleet_transparency_witness_record *records,
	size_t capacity,
	uint8_t *signature_arena,
	size_t signature_stride,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures);
int pqcp_fleet_transparency_witness_upsert(
	struct pqcp_fleet_transparency_witness_registry *registry,
	const struct pqcp_fleet_transparency_witness_authority *authority);
int pqcp_fleet_transparency_witness_revoke(
	struct pqcp_fleet_transparency_witness_registry *registry,
	const uint8_t witness_id
		[PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES],
	uint64_t revoked_at_ms);
int pqcp_fleet_transparency_witness_statement_sign(
	const struct pqcp_fleet_transparency_witness_authority *authority,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	uint64_t observed_at_ms,
	uint64_t sequence,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures,
	uint8_t *signature_storage,
	size_t signature_capacity,
	struct pqcp_fleet_transparency_witness_statement *statement);
int pqcp_fleet_transparency_witness_observe(
	struct pqcp_fleet_transparency_witness_registry *registry,
	const struct pqcp_fleet_transparency_witness_statement *statement,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	const struct pqcp_fleet_transparency_consistency_proof *consistency,
	uint64_t now_ms,
	struct pqcp_fleet_transparency_evidence *evidence);
int pqcp_fleet_transparency_witness_quorum_evaluate(
	const struct pqcp_fleet_transparency_witness_registry *registry,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	const struct pqcp_fleet_transparency_witness_policy *policy,
	uint64_t now_ms,
	struct pqcp_fleet_transparency_witness_quorum *quorum);
int pqcp_fleet_transparency_witness_registry_verify(
	const struct pqcp_fleet_transparency_witness_registry *registry);

/**
 * Exchange signed checkpoint summaries and detect split views.
 */
int pqcp_fleet_transparency_gossip_monitor_init(
	struct pqcp_fleet_transparency_gossip_monitor *monitor,
	const uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES],
	struct pqcp_fleet_transparency_gossip_peer *peers,
	size_t capacity,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures);
int pqcp_fleet_transparency_gossip_peer_upsert(
	struct pqcp_fleet_transparency_gossip_monitor *monitor,
	const struct pqcp_fleet_transparency_gossip_peer *peer);
int pqcp_fleet_transparency_gossip_message_sign(
	const struct pqcp_fleet_transparency_gossip_peer *peer,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	uint64_t sent_at_ms,
	uint64_t sequence,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures,
	uint8_t *signature_storage,
	size_t signature_capacity,
	struct pqcp_fleet_transparency_gossip_message *message);
int pqcp_fleet_transparency_gossip_submit(
	struct pqcp_fleet_transparency_gossip_monitor *monitor,
	const struct pqcp_fleet_transparency_gossip_message *message,
	const struct pqcp_fleet_transparency_consistency_proof *consistency,
	uint64_t received_at_ms,
	struct pqcp_fleet_transparency_evidence *evidence);
int pqcp_fleet_transparency_gossip_compare(
	const struct pqcp_fleet_transparency_gossip_monitor *monitor,
	const struct pqcp_fleet_transparency_checkpoint *local,
	const struct pqcp_fleet_transparency_consistency_proof *consistency,
	uint64_t now_ms,
	struct pqcp_fleet_transparency_evidence *evidence);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_TRANSPARENCY_H_ */
