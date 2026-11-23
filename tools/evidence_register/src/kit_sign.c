/*
 * SPDX-License-Identifier: MIT
 *
 * Domain-separated ML-DSA-65 sign/verify of arbitrary bytes (kit provenance).
 */

#include <errno.h>
#include <string.h>

#include <mldsa_native.h>

#include "kit_sign.h"

/* Same namespace aliasing as receipt_mldsa_ops.c: the deterministic internal
 * entry point is exported under the vendored prefix for ML-DSA-65.
 */
#define KS_MLDSA_NS(sym) PQCP_MLDSA_NATIVE_MLDSA65_##sym
#define ks_mldsa_signature_internal KS_MLDSA_NS(signature_internal)

#define CTX_MAX 255U

int kit_sign_message(const struct receipt_mldsa_ctx *key, const char *ctx,
		     const uint8_t *msg, size_t msg_len,
		     uint8_t sig[RECEIPT_MLDSA_SIG_BYTES])
{
	static const uint8_t rnd[MLDSA_RNDBYTES]; /* all zero: deterministic */
	uint8_t pre[2U + CTX_MAX];
	uint8_t out[RECEIPT_MLDSA_SIG_BYTES];
	size_t ctx_len;
	size_t out_len = 0U;

	if (key == NULL || !key->has_sk || ctx == NULL || sig == NULL ||
	    (msg == NULL && msg_len != 0U)) {
		return -EINVAL;
	}
	ctx_len = strlen(ctx);
	if (ctx_len > CTX_MAX) {
		return -EINVAL;
	}
	/* FIPS 204 pure ML-DSA: M' = 0x00 || len(ctx) || ctx || M. */
	pre[0] = 0U;
	pre[1] = (uint8_t)ctx_len;
	memcpy(pre + 2U, ctx, ctx_len);
	if (ks_mldsa_signature_internal(out, &out_len, msg, msg_len, pre,
					2U + ctx_len, rnd, key->sk, 0) != 0 ||
	    out_len != RECEIPT_MLDSA_SIG_BYTES) {
		return -EIO;
	}
	/* Cross-check through the public verify API so a wrong prefix or
	 * argument order can never silently emit a signature over the wrong
	 * bytes or under the wrong context.
	 */
	if (crypto_sign_verify(out, out_len, msg, msg_len,
			       (const uint8_t *)ctx, ctx_len, key->pk) != 0) {
		return -EIO;
	}
	memcpy(sig, out, out_len);
	return 0;
}

int kit_verify_message(const uint8_t pk[RECEIPT_MLDSA_PK_BYTES],
		       const char *ctx, const uint8_t *msg, size_t msg_len,
		       const uint8_t *sig, size_t sig_len)
{
	size_t ctx_len;

	if (pk == NULL || ctx == NULL || sig == NULL ||
	    (msg == NULL && msg_len != 0U)) {
		return -EINVAL;
	}
	ctx_len = strlen(ctx);
	if (ctx_len > CTX_MAX || sig_len != RECEIPT_MLDSA_SIG_BYTES) {
		return -EBADMSG;
	}
	return crypto_sign_verify(sig, sig_len, msg, msg_len,
				  (const uint8_t *)ctx, ctx_len, pk) == 0 ?
		       0 : -EBADMSG;
}
