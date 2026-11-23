/*
 * SPDX-License-Identifier: MIT
 *
 * Offline verification of transparent-appraisal receipts (RFC 9162 inclusion
 * proofs against an ML-DSA-65 signed checkpoint) and consistency files.
 * Pure verification: never signs, never calls randombytes.
 */

#ifndef PQCP_EVIDENCE_VERIFIER_RECEIPT_VERIFY_H_
#define PQCP_EVIDENCE_VERIFIER_RECEIPT_VERIFY_H_

#include <stdint.h>

#include "receipt_codec.h"
#include "receipt_mldsa_ops.h"

enum rv_reason {
	RV_OK = 0,
	RV_MALFORMED,
	RV_LOG_ID_MISMATCH,
	RV_BAD_SIGNATURE,
	RV_TREE_SIZE_MISMATCH,
	RV_INCLUSION_PROOF_INVALID,
	RV_EQUIVOCATION,
	RV_ROLLBACK,
	RV_CONSISTENCY_PROOF_INVALID,
	RV_INTERNAL,
};

/** Stable lowercase token used on the `reason=` output line. */
const char *rv_reason_str(enum rv_reason reason);

/**
 * Checkpoint trust check shared by receipt and consistency verification:
 * log_id and signer_key_id must equal SHA-256(pinned pk), and the ML-DSA
 * signature plus transcript digest must verify.
 */
enum rv_reason rv_check_checkpoint(struct rc_checkpoint *checkpoint,
				   const uint8_t log_pk[RECEIPT_MLDSA_PK_BYTES]);

/**
 * Verify a receipt against the pinned log key. Invariants enforced here:
 * checkpoint trust; receipt.tree_size == checkpoint.tree_size; leaf hash
 * recomputed as SHA-256(0x00 || statement); inclusion path recomputes
 * checkpoint.root. On RV_OK, leaf_hash receives the recomputed leaf hash.
 */
enum rv_reason rv_verify_receipt(
	struct rc_receipt *receipt,
	const uint8_t log_pk[RECEIPT_MLDSA_PK_BYTES],
	uint8_t leaf_hash[32]);

/**
 * Verify a consistency file: size fields, checkpoint trust, equivocation
 * detection, monotonic sequence, and the RFC 9162 consistency proof against
 * both signed roots.
 */
enum rv_reason rv_verify_consistency(
	struct rc_consistency *consistency,
	const uint8_t log_pk[RECEIPT_MLDSA_PK_BYTES]);

#endif /* PQCP_EVIDENCE_VERIFIER_RECEIPT_VERIFY_H_ */
