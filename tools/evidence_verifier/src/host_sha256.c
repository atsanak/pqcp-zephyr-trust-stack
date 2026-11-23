/*
 * SPDX-License-Identifier: MIT
 *
 * Host SHA-256 (FIPS 180-4), straightforward portable implementation.
 */

#include <errno.h>
#include <string.h>

#include "host_sha256.h"

static const uint32_t k256[64] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
	0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
	0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
	0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
	0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
	0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
	0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
	0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
	0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
	0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
	0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
	0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t rotr(uint32_t value, unsigned count)
{
	return (value >> count) | (value << (32U - count));
}

static void compress(uint32_t state[8], const uint8_t block[64])
{
	uint32_t w[64];
	uint32_t a, b, c, d, e, f, g, h;

	for (size_t i = 0U; i < 16U; ++i) {
		w[i] = ((uint32_t)block[4U * i] << 24) |
		       ((uint32_t)block[4U * i + 1U] << 16) |
		       ((uint32_t)block[4U * i + 2U] << 8) |
		       (uint32_t)block[4U * i + 3U];
	}
	for (size_t i = 16U; i < 64U; ++i) {
		uint32_t s0 = rotr(w[i - 15U], 7U) ^ rotr(w[i - 15U], 18U) ^
			      (w[i - 15U] >> 3);
		uint32_t s1 = rotr(w[i - 2U], 17U) ^ rotr(w[i - 2U], 19U) ^
			      (w[i - 2U] >> 10);

		w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
	}
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];
	for (size_t i = 0U; i < 64U; ++i) {
		uint32_t s1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t t1 = h + s1 + ch + k256[i] + w[i];
		uint32_t s0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = s0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

void host_sha256_init(struct host_sha256_ctx *ctx)
{
	static const uint32_t iv[8] = {
		0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
		0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
	};

	memcpy(ctx->state, iv, sizeof(iv));
	ctx->total_bytes = 0U;
	ctx->block_used = 0U;
	memset(ctx->block, 0, sizeof(ctx->block));
}

void host_sha256_update(struct host_sha256_ctx *ctx, const uint8_t *data,
			size_t length)
{
	if (length == 0U) {
		return;
	}
	ctx->total_bytes += length;
	while (length > 0U) {
		size_t room = HOST_SHA256_BLOCK_BYTES - ctx->block_used;
		size_t take = length < room ? length : room;

		memcpy(ctx->block + ctx->block_used, data, take);
		ctx->block_used += take;
		data += take;
		length -= take;
		if (ctx->block_used == HOST_SHA256_BLOCK_BYTES) {
			compress(ctx->state, ctx->block);
			ctx->block_used = 0U;
		}
	}
}

void host_sha256_final(struct host_sha256_ctx *ctx,
		       uint8_t digest[HOST_SHA256_DIGEST_BYTES])
{
	uint64_t bit_length = ctx->total_bytes * 8U;

	ctx->block[ctx->block_used++] = 0x80U;
	if (ctx->block_used > 56U) {
		memset(ctx->block + ctx->block_used, 0,
		       HOST_SHA256_BLOCK_BYTES - ctx->block_used);
		compress(ctx->state, ctx->block);
		ctx->block_used = 0U;
	}
	memset(ctx->block + ctx->block_used, 0, 56U - ctx->block_used);
	for (size_t i = 0U; i < 8U; ++i) {
		ctx->block[56U + i] = (uint8_t)(bit_length >> (56U - 8U * i));
	}
	compress(ctx->state, ctx->block);
	for (size_t i = 0U; i < 8U; ++i) {
		digest[4U * i] = (uint8_t)(ctx->state[i] >> 24);
		digest[4U * i + 1U] = (uint8_t)(ctx->state[i] >> 16);
		digest[4U * i + 2U] = (uint8_t)(ctx->state[i] >> 8);
		digest[4U * i + 3U] = (uint8_t)ctx->state[i];
	}
	memset(ctx, 0, sizeof(*ctx));
}

void host_sha256(const uint8_t *data, size_t length,
		 uint8_t digest[HOST_SHA256_DIGEST_BYTES])
{
	struct host_sha256_ctx ctx;

	host_sha256_init(&ctx);
	host_sha256_update(&ctx, data, length);
	host_sha256_final(&ctx, digest);
}

void host_sha256_hex(const uint8_t digest[HOST_SHA256_DIGEST_BYTES],
		     char out[HOST_SHA256_DIGEST_BYTES * 2U + 1U])
{
	static const char hex[] = "0123456789abcdef";

	for (size_t i = 0U; i < HOST_SHA256_DIGEST_BYTES; ++i) {
		out[2U * i] = hex[digest[i] >> 4];
		out[2U * i + 1U] = hex[digest[i] & 0x0fU];
	}
	out[HOST_SHA256_DIGEST_BYTES * 2U] = '\0';
}

static int parts_digest(void *context,
			const struct pqcp_fleet_transparency_part *parts,
			size_t part_count,
			uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	struct host_sha256_ctx ctx;

	(void)context;
	if (output == NULL || (parts == NULL && part_count != 0U)) {
		return -EINVAL;
	}
	host_sha256_init(&ctx);
	for (size_t i = 0U; i < part_count; ++i) {
		if (parts[i].data == NULL && parts[i].length != 0U) {
			return -EINVAL;
		}
		host_sha256_update(&ctx, parts[i].data, parts[i].length);
	}
	host_sha256_final(&ctx, output);
	return 0;
}

void host_sha256_hash_ops(struct pqcp_fleet_transparency_hash_ops *ops)
{
	ops->context = NULL;
	ops->digest = parts_digest;
}
