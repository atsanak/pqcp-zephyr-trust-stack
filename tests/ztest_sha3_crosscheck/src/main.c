/* SPDX-License-Identifier: MIT */
/*
 * The SHA3 inside mlkem-native is checked against the SHA3 of Zephyr's crypto
 * API (Mbed TLS behind the PSA layer), an implementation that shares no code
 * with it. Input lengths cover every size up to 300 bytes, which includes both
 * rate boundaries (136 bytes for SHA3-256 and 72 bytes for SHA3-512), and a
 * set of longer pseudo random sizes. A flipped input bit has to change both
 * digests, which shows the comparison is able to fail.
 */

#include <stdint.h>
#include <string.h>

#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/hash.h>
#include <zephyr/device.h>
#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/mlkem.h>

/* Exported by the single level ML-KEM-768 build. */
void PQCP_MLKEM_NATIVE_MLKEM768_sha3_256(uint8_t *out, const uint8_t *in,
					 size_t inlen);
void PQCP_MLKEM_NATIVE_MLKEM768_sha3_512(uint8_t *out, const uint8_t *in,
					 size_t inlen);

#define MAX_LEN 1500U

static uint8_t input[MAX_LEN];
static uint32_t rng_state = 0x2545F491U;

static uint32_t next_rand(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

static void zephyr_sha3(enum hash_algo algo, const uint8_t *in, size_t len,
			uint8_t *out)
{
	const struct device *dev =
		device_get_binding(CONFIG_CRYPTO_MBEDTLS_SHIM_DRV_NAME);
	struct hash_ctx ctx = {.flags = CAP_SYNC_OPS | CAP_SEPARATE_IO_BUFS};
	struct hash_pkt pkt = {.in_buf = in, .in_len = len, .out_buf = out};

	zassert_not_null(dev, "crypto shim device missing");
	zassert_equal(hash_begin_session(dev, &ctx, algo), 0);
	zassert_equal(hash_compute(&ctx, &pkt), 0);
	hash_free_session(dev, &ctx);
}

static unsigned int compare_length(size_t len)
{
	uint8_t lib256[32], ref256[32], lib512[64], ref512[64];

	PQCP_MLKEM_NATIVE_MLKEM768_sha3_256(lib256, input, len);
	zephyr_sha3(CRYPTO_HASH_ALGO_SHA3_256, input, len, ref256);
	PQCP_MLKEM_NATIVE_MLKEM768_sha3_512(lib512, input, len);
	zephyr_sha3(CRYPTO_HASH_ALGO_SHA3_512, input, len, ref512);
	return (memcmp(lib256, ref256, sizeof(lib256)) != 0U) +
	       (memcmp(lib512, ref512, sizeof(lib512)) != 0U);
}

ZTEST(pqcp_sha3_crosscheck, test_library_sha3_matches_zephyr_sha3)
{
	unsigned int mismatches = 0U;
	unsigned int cases = 0U;
	uint8_t lib256[32], lib512[64], flipped256[32], flipped512[64];

	for (size_t i = 0U; i < MAX_LEN; ++i) {
		input[i] = (uint8_t)next_rand();
	}
	for (size_t len = 0U; len <= 300U; ++len) {
		mismatches += compare_length(len);
		cases++;
	}
	for (unsigned int k = 0U; k < 700U; ++k) {
		const size_t len = 301U + (next_rand() % (MAX_LEN - 300U));

		mismatches += compare_length(len);
		cases++;
	}

	/* Positive control, one flipped bit changes both library digests. */
	PQCP_MLKEM_NATIVE_MLKEM768_sha3_256(lib256, input, 200U);
	PQCP_MLKEM_NATIVE_MLKEM768_sha3_512(lib512, input, 200U);
	input[100] ^= 0x01U;
	PQCP_MLKEM_NATIVE_MLKEM768_sha3_256(flipped256, input, 200U);
	PQCP_MLKEM_NATIVE_MLKEM768_sha3_512(flipped512, input, 200U);
	input[100] ^= 0x01U;
	zassert_not_equal(memcmp(lib256, flipped256, sizeof(lib256)), 0);
	zassert_not_equal(memcmp(lib512, flipped512, sizeof(lib512)), 0);

	printk("PQCP_SHA3_CROSSCHECK lengths=%u mismatches=%u control=detected\n",
	       cases, mismatches);
	zassert_equal(mismatches, 0U, "%u digest mismatches", mismatches);
}

ZTEST_SUITE(pqcp_sha3_crosscheck, NULL, NULL, NULL, NULL, NULL);
