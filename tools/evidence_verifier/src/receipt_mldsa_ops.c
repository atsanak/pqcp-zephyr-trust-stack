/*
 * SPDX-License-Identifier: MIT
 *
 * ML-DSA-65 provider for the fleet transparency signature_ops table.
 */

#include <errno.h>
#include <string.h>

#include <mldsa_native.h>

#include "host_sha256.h"
#include "receipt_mldsa_ops.h"

#define MESSAGE_MAX 512U

/* mldsa_native.h only aliases the SUPERCOP names (crypto_sign_verify, ...);
 * the deterministic internal entry points are exported under the vendored
 * namespace prefix selected in mldsa_native_config.h for ML-DSA-65. A wrong
 * prefix fails at compile time (undeclared) or link time, never silently.
 */
#define RC_MLDSA_NS(sym) PQCP_MLDSA_NATIVE_MLDSA65_##sym
#define rc_mldsa_keypair_internal RC_MLDSA_NS(keypair_internal)
#define rc_mldsa_signature_internal RC_MLDSA_NS(signature_internal)

static int flatten(const struct pqcp_fleet_transparency_part *parts,
		   size_t part_count, uint8_t *out, size_t *out_len)
{
	size_t used = 0U;

	if (parts == NULL && part_count != 0U) {
		return -EINVAL;
	}
	for (size_t i = 0U; i < part_count; ++i) {
		if (parts[i].length > MESSAGE_MAX - used ||
		    (parts[i].data == NULL && parts[i].length != 0U)) {
			return -EMSGSIZE;
		}
		if (parts[i].length != 0U) {
			memcpy(out + used, parts[i].data, parts[i].length);
		}
		used += parts[i].length;
	}
	*out_len = used;
	return 0;
}

void receipt_mldsa_key_id(const uint8_t pk[RECEIPT_MLDSA_PK_BYTES],
			  uint8_t key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES])
{
	host_sha256(pk, RECEIPT_MLDSA_PK_BYTES, key_id);
}

int receipt_mldsa_keypair_from_seed(
	const uint8_t seed[RECEIPT_MLDSA_SEED_BYTES],
	uint8_t pk[RECEIPT_MLDSA_PK_BYTES],
	uint8_t sk[RECEIPT_MLDSA_SK_BYTES])
{
	if (seed == NULL || pk == NULL || sk == NULL) {
		return -EINVAL;
	}
	return rc_mldsa_keypair_internal(pk, sk, seed) == 0 ? 0 : -EIO;
}

void receipt_mldsa_ctx_init_verify(struct receipt_mldsa_ctx *ctx,
				   const uint8_t pk[RECEIPT_MLDSA_PK_BYTES])
{
	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->pk, pk, RECEIPT_MLDSA_PK_BYTES);
	receipt_mldsa_key_id(ctx->pk, ctx->key_id);
}

int receipt_mldsa_ctx_init_sign(
	struct receipt_mldsa_ctx *ctx,
	const uint8_t seed[RECEIPT_MLDSA_SEED_BYTES])
{
	memset(ctx, 0, sizeof(*ctx));
	if (receipt_mldsa_keypair_from_seed(seed, ctx->pk, ctx->sk) != 0) {
		return -EIO;
	}
	ctx->has_sk = true;
	receipt_mldsa_key_id(ctx->pk, ctx->key_id);
	return 0;
}

static int ops_sign(void *context,
		    const uint8_t key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES],
		    const struct pqcp_fleet_transparency_part *parts,
		    size_t part_count, uint8_t *signature,
		    size_t signature_capacity, size_t *signature_length)
{
	struct receipt_mldsa_ctx *ctx = context;
	static const uint8_t rnd[MLDSA_RNDBYTES]; /* all zero: deterministic */
	const size_t ctx_len = sizeof(RECEIPT_MLDSA_CONTEXT) - 1U;
	uint8_t pre[2U + sizeof(RECEIPT_MLDSA_CONTEXT)];
	uint8_t message[MESSAGE_MAX];
	uint8_t sig[RECEIPT_MLDSA_SIG_BYTES];
	size_t message_len;
	size_t sig_len = 0U;
	int ret;

	if (ctx == NULL || !ctx->has_sk || key_id == NULL ||
	    signature == NULL || signature_length == NULL ||
	    memcmp(key_id, ctx->key_id, sizeof(ctx->key_id)) != 0) {
		return -EINVAL;
	}
	if (signature_capacity < RECEIPT_MLDSA_SIG_BYTES) {
		return -ENOSPC;
	}
	ret = flatten(parts, part_count, message, &message_len);
	if (ret != 0) {
		return ret;
	}
	/* FIPS 204 pure ML-DSA: M' = 0x00 || len(ctx) || ctx || M. The
	 * internal API takes the 0x00||len||ctx prefix separately.
	 */
	pre[0] = 0U;
	pre[1] = (uint8_t)ctx_len;
	memcpy(pre + 2U, RECEIPT_MLDSA_CONTEXT, ctx_len);
	if (rc_mldsa_signature_internal(sig, &sig_len, message,
					   message_len, pre, 2U + ctx_len,
					   rnd, ctx->sk, 0) != 0 ||
	    sig_len != RECEIPT_MLDSA_SIG_BYTES) {
		return -EIO;
	}
	/* Cross-check through the public verify API so a wrong prefix or
	 * argument order can never silently emit a signature over the wrong
	 * bytes.
	 */
	if (crypto_sign_verify(sig, sig_len, message, message_len,
			       (const uint8_t *)RECEIPT_MLDSA_CONTEXT, ctx_len,
			       ctx->pk) != 0) {
		return -EIO;
	}
	memcpy(signature, sig, sig_len);
	*signature_length = sig_len;
	return 0;
}

static int ops_verify(
	void *context,
	const uint8_t key_id[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES],
	const struct pqcp_fleet_transparency_part *parts, size_t part_count,
	const uint8_t *signature, size_t signature_length)
{
	struct receipt_mldsa_ctx *ctx = context;
	uint8_t message[MESSAGE_MAX];
	size_t message_len;
	int ret;

	if (ctx == NULL || key_id == NULL || signature == NULL) {
		return -EINVAL;
	}
	if (memcmp(key_id, ctx->key_id, sizeof(ctx->key_id)) != 0) {
		return -EACCES;
	}
	if (signature_length != RECEIPT_MLDSA_SIG_BYTES) {
		return -EBADMSG;
	}
	ret = flatten(parts, part_count, message, &message_len);
	if (ret != 0) {
		return ret;
	}
	return crypto_sign_verify(
		       signature, signature_length, message, message_len,
		       (const uint8_t *)RECEIPT_MLDSA_CONTEXT,
		       sizeof(RECEIPT_MLDSA_CONTEXT) - 1U, ctx->pk) == 0 ?
		       0 : -EBADMSG;
}

void receipt_mldsa_signature_ops(
	struct pqcp_fleet_transparency_signature_ops *ops,
	struct receipt_mldsa_ctx *ctx)
{
	ops->context = ctx;
	ops->sign = ops_sign;
	ops->verify = ops_verify;
}
