/*
 * SPDX-License-Identifier: MIT
 *
 * ML-DSA-65 provider for the fleet transparency signature_ops table.
 *
 * key_id = SHA-256(public key). Signing is the deterministic FIPS 204
 * variant (rnd = 32 zero bytes) and never touches randombytes, so the
 * verifier (whose randombytes stub aborts) and the register tool (which is
 * seed-file driven) stay reproducible. Verification uses the public
 * crypto_sign_verify API, which is also what the sign path is cross-checked
 * against.
 */

#ifndef PQCP_EVIDENCE_VERIFIER_RECEIPT_MLDSA_OPS_H_
#define PQCP_EVIDENCE_VERIFIER_RECEIPT_MLDSA_OPS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/fleet_transparency.h>

#define RECEIPT_MLDSA_PK_BYTES 1952U
#define RECEIPT_MLDSA_SK_BYTES 4032U
#define RECEIPT_MLDSA_SIG_BYTES 3309U
#define RECEIPT_MLDSA_SEED_BYTES 32U
#define RECEIPT_MLDSA_CONTEXT "PQCP-APPRAISAL-LOG-V1"

struct receipt_mldsa_ctx {
	uint8_t pk[RECEIPT_MLDSA_PK_BYTES];
	uint8_t sk[RECEIPT_MLDSA_SK_BYTES];
	uint8_t key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES];
	bool has_sk;
};

/** key_id = SHA-256(pk). */
void receipt_mldsa_key_id(const uint8_t pk[RECEIPT_MLDSA_PK_BYTES],
			  uint8_t key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES]);

/** Deterministic keypair from a 32-byte seed (no randomness). 0 on success. */
int receipt_mldsa_keypair_from_seed(
	const uint8_t seed[RECEIPT_MLDSA_SEED_BYTES],
	uint8_t pk[RECEIPT_MLDSA_PK_BYTES],
	uint8_t sk[RECEIPT_MLDSA_SK_BYTES]);

/** Verify-only context pinned to one public key. */
void receipt_mldsa_ctx_init_verify(struct receipt_mldsa_ctx *ctx,
				   const uint8_t pk[RECEIPT_MLDSA_PK_BYTES]);

/** Signing context (keypair derived from seed). 0 on success. */
int receipt_mldsa_ctx_init_sign(
	struct receipt_mldsa_ctx *ctx,
	const uint8_t seed[RECEIPT_MLDSA_SEED_BYTES]);

/** Fill a signature_ops table bound to ctx (sign needs has_sk). */
void receipt_mldsa_signature_ops(
	struct pqcp_fleet_transparency_signature_ops *ops,
	struct receipt_mldsa_ctx *ctx);

#endif /* PQCP_EVIDENCE_VERIFIER_RECEIPT_MLDSA_OPS_H_ */
