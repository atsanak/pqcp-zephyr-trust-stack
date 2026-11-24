/* SPDX-License-Identifier: MIT */
/*
 * Workload for the memory residue check of key generation and encapsulation.
 *
 * Each region runs one call with a reseeded deterministic generator. Before
 * the region the harness draws the same random bytes from an identical
 * generator state and prints them, and after the region it prints the outputs.
 * The residue analysis looks for those values in the stack words the call left
 * behind. Labels are (entry << 8) | key with entry 0 for ML-KEM key
 * generation, 1 for ML-KEM encapsulation and 2 for ML-DSA key generation.
 */

#include <string.h>

#include <zephyr/irq.h>
#include <zephyr/ztest.h>
#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

#define CT_KEYS 4U

static uint8_t kem_pk[PQCP_MLKEM_768_PK_SIZE];
static uint8_t kem_sk[PQCP_MLKEM_768_SK_SIZE];
static uint8_t kem_ct[PQCP_MLKEM_768_CT_SIZE];
static uint8_t kem_ss[PQCP_MLKEM_SS_SIZE];
static uint8_t dsa_pk[PQCP_MLDSA_65_PK_SIZE];
static uint8_t dsa_sk[PQCP_MLDSA_65_SK_SIZE];

__attribute__((noinline)) void pqcp_ct_region_begin(uint32_t label)
{
	__asm__ volatile("" : : "r"(label) : "memory");
}

__attribute__((noinline)) void pqcp_ct_region_end(uint32_t label)
{
	__asm__ volatile("" : : "r"(label) : "memory");
}

static void reseed(uint32_t entry, uint32_t key)
{
	uint8_t seed[32];

	memset(seed, 0, sizeof(seed));
	memcpy(seed, "PQCP-CT-RESIDUE", 15U);
	seed[16] = (uint8_t)entry;
	seed[17] = (uint8_t)key;
	zassert_equal(pqcp_rng_deterministic_seed(seed, sizeof(seed)),
		      PQCP_RNG_SUCCESS);
}

static void print_dict(uint32_t label, const char *what, const uint8_t *p,
		       size_t n)
{
	printk("PQCP_CT_DICT label=%u kind=%s ", (unsigned int)label, what);
	for (size_t i = 0U; i < n; ++i) {
		printk("%02x", p[i]);
	}
	printk("\n");
}

/* Draw the bytes the call will draw, then restore the generator. */
static void print_random(uint32_t entry, uint32_t key, uint32_t label,
			 size_t n)
{
	uint8_t buf[64];

	reseed(entry, key);
	zassert_equal(pqcp_rng_get_bytes(buf, n), PQCP_RNG_SUCCESS);
	print_dict(label, "random", buf, n);
	reseed(entry, key);
}

ZTEST(pqcp_ct_residue, test_keygen_and_encaps_residue)
{
	for (uint32_t key = 0U; key < CT_KEYS; ++key) {
		/* ML-KEM key generation draws d and z, 64 bytes. */
		uint32_t label = (0U << 8) | key;
		unsigned int irq;

		print_random(0U, key, label, 64U);
		irq = irq_lock();
		pqcp_ct_region_begin(label);
		(void)pqcp_mlkem_keypair(PQCP_MLKEM_768, kem_pk, kem_sk);
		pqcp_ct_region_end(label);
		irq_unlock(irq);
		print_dict(label, "output", kem_sk, sizeof(kem_sk));

		/* ML-KEM encapsulation draws the message m, 32 bytes. */
		label = (1U << 8) | key;
		print_random(1U, key, label, 32U);
		irq = irq_lock();
		pqcp_ct_region_begin(label);
		(void)pqcp_mlkem_encapsulate(PQCP_MLKEM_768, kem_pk, kem_ct,
					     kem_ss);
		pqcp_ct_region_end(label);
		irq_unlock(irq);
		print_dict(label, "output", kem_ss, sizeof(kem_ss));

		/* ML-DSA key generation draws the 32 byte seed. */
		label = (2U << 8) | key;
		print_random(2U, key, label, 32U);
		irq = irq_lock();
		pqcp_ct_region_begin(label);
		(void)pqcp_mldsa_keypair(PQCP_MLDSA_65, dsa_pk, dsa_sk);
		pqcp_ct_region_end(label);
		irq_unlock(irq);
		print_dict(label, "output", dsa_sk, sizeof(dsa_sk));
	}
	printk("PQCP_CT_TRACE_APP alg=RESIDUE keys=%u regions=%u\n", CT_KEYS,
	       3U * CT_KEYS);
}

ZTEST_SUITE(pqcp_ct_residue, NULL, NULL, NULL, NULL, NULL);
