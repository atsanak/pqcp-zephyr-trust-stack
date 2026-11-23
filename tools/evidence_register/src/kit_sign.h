/*
 * SPDX-License-Identifier: MIT
 *
 * Domain-separated ML-DSA-65 sign/verify of an arbitrary file's bytes, used
 * to sign the evidence-verifier kit provenance (docs/kit-provenance.md).
 *
 * Signing is deterministic FIPS 204 pure ML-DSA (rnd = 32 zero bytes) under
 * the context string KIT_SIGN_CONTEXT_KIT, which is distinct from the log
 * checkpoint context (RECEIPT_MLDSA_CONTEXT). A signature made under one
 * context never verifies under the other. Neither function reads
 * randomness. Every signature is cross-checked through the public
 * crypto_sign_verify API before it is returned.
 */

#ifndef PQCP_EVIDENCE_REGISTER_KIT_SIGN_H_
#define PQCP_EVIDENCE_REGISTER_KIT_SIGN_H_

#include <stddef.h>
#include <stdint.h>

#include "receipt_mldsa_ops.h"

#define KIT_SIGN_CONTEXT_KIT "PQCP-KIT-PROVENANCE-V1"

/** Sign msg under ctx (ctx_len <= 255). 0 on success. */
int kit_sign_message(const struct receipt_mldsa_ctx *key, const char *ctx,
		     const uint8_t *msg, size_t msg_len,
		     uint8_t sig[RECEIPT_MLDSA_SIG_BYTES]);

/** 0 when sig is a valid signature of msg under pk and ctx, else -EBADMSG. */
int kit_verify_message(const uint8_t pk[RECEIPT_MLDSA_PK_BYTES],
		       const char *ctx, const uint8_t *msg, size_t msg_len,
		       const uint8_t *sig, size_t sig_len);

#endif /* PQCP_EVIDENCE_REGISTER_KIT_SIGN_H_ */
