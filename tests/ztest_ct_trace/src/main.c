/*
 * SPDX-License-Identifier: MIT
 *
 * Workload for the relational leakage test of ML-KEM-768 decapsulation.
 *
 * For each of CT_TRACE_KEYS deterministic key pairs the test decapsulates a
 * valid ciphertext (label 0) and a corrupted one (label 1, implicit
 * rejection path), each bracketed by the marker functions the pqcp_ct_trace
 * TCG plugin hooks (scripts/run_ct_trace_checks.py). The secrets differ per
 * key; the ciphertext differs per key and per class. The runner requires
 * every region to be indistinguishable on every observation channel.
 *
 * Interrupts are locked inside a region so a timer ISR cannot appear in the
 * trace. Run without the plugin this is a plain decapsulation smoke test.
 */

#include <stdint.h>
#include <string.h>

#include <zephyr/irq.h>
#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

#define CT_TRACE_KEYS 8U
#define CT_TRACE_CTS 6U /* 1 valid + 5 corrupted ciphertexts per key */

static uint8_t public_key[PQCP_MLKEM_768_PK_SIZE];
static uint8_t secret_key[PQCP_MLKEM_768_SK_SIZE];
static uint8_t valid_ct[PQCP_MLKEM_768_CT_SIZE];
/* Every region decapsulates from this one buffer, so data addresses of the
 * ciphertext can never differ between regions by construction.
 */
static uint8_t work_ct[PQCP_MLKEM_768_CT_SIZE];
static uint8_t shared_secret[PQCP_MLKEM_SS_SIZE];

/* The plugin reads the label from the first argument register (rdi). */
__attribute__((noinline)) void pqcp_ct_region_begin(uint32_t label)
{
	__asm__ volatile("" : : "r"(label) : "memory");
}

__attribute__((noinline)) void pqcp_ct_region_end(uint32_t label)
{
	__asm__ volatile("" : : "r"(label) : "memory");
}

static void seed_for_key(uint32_t key)
{
	uint8_t seed[32];

	memset(seed, 0, sizeof(seed));
	memcpy(seed, "PQCP-CT-TRACE", 13U);
	seed[16] = (uint8_t)key;
	seed[17] = (uint8_t)(key * 37U + 11U);
	zassert_equal(pqcp_rng_deterministic_seed(seed, sizeof(seed)),
		      PQCP_RNG_SUCCESS);
}

static void run_region(uint32_t label)
{
	const unsigned int irq = irq_lock();

	pqcp_ct_region_begin(label);
	(void)pqcp_mlkem_decapsulate(PQCP_MLKEM_768, work_ct, secret_key,
				     shared_secret);
	pqcp_ct_region_end(label);
	irq_unlock(irq);
}

/*
 * Relation under test: for a FIXED key, decapsulating any ciphertext (the
 * valid one, or corruptions at different positions and values, which drive
 * the implicit-rejection path and different re-encryption comparisons) must
 * leave an identical trace. Label = key << 8 | ciphertext index. Traces of
 * different keys may differ (the public matrix is expanded by rejection
 * sampling from the public seed); the runner reports that separately.
 */
ZTEST(pqcp_ct_trace, test_decap_relational_trace_regions)
{
	for (uint32_t key = 0U; key < CT_TRACE_KEYS; ++key) {
		seed_for_key(key);
		zassert_equal(pqcp_mlkem_keypair(PQCP_MLKEM_768, public_key,
						 secret_key),
			      PQCP_MLKEM_SUCCESS);
		zassert_equal(pqcp_mlkem_encapsulate(PQCP_MLKEM_768,
						     public_key, valid_ct,
						     shared_secret),
			      PQCP_MLKEM_SUCCESS);

		for (uint32_t c = 0U; c < CT_TRACE_CTS; ++c) {
			memcpy(work_ct, valid_ct, sizeof(work_ct));
			if (c > 0U) {
				work_ct[(c * 197U) % sizeof(work_ct)] ^=
					(uint8_t)(0x11U * c);
				work_ct[sizeof(work_ct) - c] ^= 0x5AU;
			}
			run_region((key << 8) | c);
		}
	}
	printk("PQCP_CT_TRACE_APP alg=MLKEM-768 keys=%u regions=%u\n",
	       CT_TRACE_KEYS, CT_TRACE_KEYS * CT_TRACE_CTS);
}

ZTEST_SUITE(pqcp_ct_trace, NULL, NULL, NULL, NULL, NULL);
