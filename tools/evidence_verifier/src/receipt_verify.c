/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Offline verification of transparent-appraisal receipts and consistency
 * files (see receipt_verify.h).
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "host_sha256.h"
#include "receipt_verify.h"

const char *rv_reason_str(enum rv_reason reason)
{
	switch (reason) {
	case RV_OK:
		return "ok";
	case RV_MALFORMED:
		return "malformed";
	case RV_LOG_ID_MISMATCH:
		return "log_id_mismatch";
	case RV_BAD_SIGNATURE:
		return "bad_signature";
	case RV_TREE_SIZE_MISMATCH:
		return "tree_size_mismatch";
	case RV_INCLUSION_PROOF_INVALID:
		return "inclusion_proof_invalid";
	case RV_EQUIVOCATION:
		return "equivocation";
	case RV_ROLLBACK:
		return "rollback";
	case RV_CONSISTENCY_PROOF_INVALID:
		return "consistency_proof_invalid";
	case RV_INTERNAL:
	default:
		return "internal_error";
	}
}

enum rv_reason rv_check_checkpoint(struct rc_checkpoint *checkpoint,
				   const uint8_t log_pk[RECEIPT_MLDSA_PK_BYTES])
{
	struct pqcp_fleet_transparency_hash_ops hash;
	struct pqcp_fleet_transparency_signature_ops sigops;
	struct pqcp_fleet_transparency_checkpoint fleet;
	struct receipt_mldsa_ctx ctx;

	receipt_mldsa_ctx_init_verify(&ctx, log_pk);
	if (memcmp(checkpoint->log_id, ctx.key_id, 32U) != 0 ||
	    memcmp(checkpoint->signer_key_id, ctx.key_id, 32U) != 0) {
		return RV_LOG_ID_MISMATCH;
	}
	host_sha256_hash_ops(&hash);
	receipt_mldsa_signature_ops(&sigops, &ctx);
	rc_checkpoint_to_fleet(checkpoint, &fleet);
	if (pqcp_fleet_transparency_checkpoint_verify(&fleet, &hash,
						      &sigops) != 0) {
		return RV_BAD_SIGNATURE;
	}
	return RV_OK;
}

enum rv_reason rv_verify_receipt(
	struct rc_receipt *receipt,
	const uint8_t log_pk[RECEIPT_MLDSA_PK_BYTES],
	uint8_t leaf_hash[32])
{
	struct pqcp_fleet_transparency_hash_ops hash;
	struct pqcp_fleet_transparency_inclusion_proof *proof;
	enum rv_reason reason;

	reason = rv_check_checkpoint(&receipt->checkpoint, log_pk);
	if (reason != RV_OK) {
		return reason;
	}
	/* Invariant 2: the proof must be bound to the signed checkpoint, not
	 * to whatever size the receipt claims. The proof root is taken from
	 * the checkpoint, never from the receipt file.
	 */
	if (receipt->tree_size != receipt->checkpoint.tree_size) {
		return RV_TREE_SIZE_MISMATCH;
	}
	proof = calloc(1U, sizeof(*proof));
	if (proof == NULL) {
		return RV_INTERNAL;
	}
	host_sha256_hash_ops(&hash);
	proof->schema_version = PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	proof->tree_size = receipt->checkpoint.tree_size;
	proof->leaf_index = receipt->leaf_index;
	memcpy(proof->root, receipt->checkpoint.root, 32U);
	/* Invariant 3: leaf hash recomputed, never trusted from a file. */
	if (pqcp_fleet_transparency_leaf_hash(
		    &hash, receipt->statement, receipt->statement_length,
		    proof->leaf_hash) != 0) {
		free(proof);
		return RV_INTERNAL;
	}
	proof->node_count = receipt->path_count;
	memcpy(proof->nodes, receipt->path,
	       receipt->path_count * 32U);
	if (pqcp_fleet_transparency_inclusion_proof_verify(&hash, proof) !=
	    0) {
		free(proof);
		return RV_INCLUSION_PROOF_INVALID;
	}
	if (leaf_hash != NULL) {
		memcpy(leaf_hash, proof->leaf_hash, 32U);
	}
	free(proof);
	return RV_OK;
}

enum rv_reason rv_verify_consistency(
	struct rc_consistency *c,
	const uint8_t log_pk[RECEIPT_MLDSA_PK_BYTES])
{
	struct pqcp_fleet_transparency_hash_ops hash;
	struct pqcp_fleet_transparency_consistency_proof *proof;
	enum rv_reason reason;
	const struct rc_checkpoint *o = &c->old_checkpoint;
	const struct rc_checkpoint *n = &c->new_checkpoint;

	if (c->old_size != o->tree_size || c->new_size != n->tree_size) {
		return RV_MALFORMED;
	}
	reason = rv_check_checkpoint(&c->old_checkpoint, log_pk);
	if (reason == RV_OK) {
		reason = rv_check_checkpoint(&c->new_checkpoint, log_pk);
	}
	if (reason != RV_OK) {
		return reason;
	}
	if (memcmp(o->log_id, n->log_id, 32U) != 0) {
		return RV_LOG_ID_MISMATCH;
	}
	/* Both checkpoints carry valid signatures from here on, so any
	 * contradiction between them is attributable to the log operator.
	 */
	if ((o->tree_size == n->tree_size &&
	     memcmp(o->root, n->root, 32U) != 0) ||
	    (o->sequence == n->sequence &&
	     (o->tree_size != n->tree_size ||
	      memcmp(o->root, n->root, 32U) != 0))) {
		return RV_EQUIVOCATION;
	}
	if (n->sequence <= o->sequence || n->tree_size < o->tree_size) {
		return RV_ROLLBACK;
	}
	proof = calloc(1U, sizeof(*proof));
	if (proof == NULL) {
		return RV_INTERNAL;
	}
	host_sha256_hash_ops(&hash);
	proof->schema_version = PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	proof->old_tree_size = o->tree_size;
	proof->new_tree_size = n->tree_size;
	memcpy(proof->old_root, o->root, 32U);
	memcpy(proof->new_root, n->root, 32U);
	proof->node_count = c->node_count;
	memcpy(proof->nodes, c->nodes, c->node_count * 32U);
	if (pqcp_fleet_transparency_consistency_proof_verify(&hash, proof) !=
	    0) {
		free(proof);
		return RV_CONSISTENCY_PROOF_INVALID;
	}
	free(proof);
	return RV_OK;
}
