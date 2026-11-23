/*
 * SPDX-License-Identifier: MIT
 *
 * Host SHA-256 (FIPS 180-4) plus the transparency-log hash_ops adapter.
 * Host-only: the firmware keeps its own provider (fleet_sha256.c).
 */

#ifndef PQCP_EVIDENCE_VERIFIER_HOST_SHA256_H_
#define PQCP_EVIDENCE_VERIFIER_HOST_SHA256_H_

#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/fleet_transparency.h>

#define HOST_SHA256_DIGEST_BYTES 32U
#define HOST_SHA256_BLOCK_BYTES 64U

struct host_sha256_ctx {
	uint32_t state[8];
	uint64_t total_bytes;
	uint8_t block[HOST_SHA256_BLOCK_BYTES];
	size_t block_used;
};

void host_sha256_init(struct host_sha256_ctx *ctx);
void host_sha256_update(struct host_sha256_ctx *ctx, const uint8_t *data,
			size_t length);
void host_sha256_final(struct host_sha256_ctx *ctx,
		       uint8_t digest[HOST_SHA256_DIGEST_BYTES]);
void host_sha256(const uint8_t *data, size_t length,
		 uint8_t digest[HOST_SHA256_DIGEST_BYTES]);

/** Lowercase hex of a digest into out[65] (NUL terminated). */
void host_sha256_hex(const uint8_t digest[HOST_SHA256_DIGEST_BYTES],
		     char out[HOST_SHA256_DIGEST_BYTES * 2U + 1U]);

/** Fill a transparency hash_ops table that hashes parts[] with SHA-256. */
void host_sha256_hash_ops(struct pqcp_fleet_transparency_hash_ops *ops);

#endif /* PQCP_EVIDENCE_VERIFIER_HOST_SHA256_H_ */
