/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Workload for the declassification-aware relational leakage test of
 * ML-DSA-65 signing.
 *
 * Signing rejects and retries, so the whole-signature trace legitimately
 * depends on the secret through the number of iterations. mldsa-native
 * annotates exactly those points (and every other secret->public flow) with
 * MLD_CT_TESTING_DECLASSIFY. The shim valgrind header turns each annotation
 * into pqcp_ct_declassify(), which reports (call site, length, value class)
 * to the plugin; the plugin cuts the trace into segments at those events.
 *
 * Relation under test: two signing runs that agree on every declassified
 * value so far must execute the next segment identically on every channel.
 *
 * Input family: for each message, the secret components that signing
 * consumes (s1, s2, t0) are varied while everything that feeds the public
 * path (rho, K, tr, message, hedging randomness) is held fixed. The
 * commitment w = A*y, and hence the first challenge, is then identical across
 * variants, so segments are comparable. The crafted keys are not valid key
 * pairs; signing does not check consistency, and only the trace is examined.
 */

#include <stdint.h>
#include <string.h>

#include <zephyr/irq.h>
#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#define CT_MSGS 3U
#define CT_VARIANTS 6U
#define CT_MSG_LEN 48U

/* ML-DSA-65 secret key layout: rho(32) K(32) tr(64) s1 s2 t0. */
#define SK_S1_OFF (32U + 32U + 64U)
#define SK_ETA_POLY 128U /* eta = 4: 4 bits per coefficient */
#define SK_S1_LEN (5U * SK_ETA_POLY)
#define SK_S2_OFF (SK_S1_OFF + SK_S1_LEN)
#define SK_S2_LEN (6U * SK_ETA_POLY)
#define SK_T0_OFF (SK_S2_OFF + SK_S2_LEN)
#define SK_T0_LEN (6U * 416U)

static uint8_t public_key[PQCP_MLDSA_65_PK_SIZE];
static uint8_t base_sk[PQCP_MLDSA_65_SK_SIZE];
static uint8_t work_sk[PQCP_MLDSA_65_SK_SIZE];
static uint8_t signature[PQCP_MLDSA_65_SIG_SIZE];
static uint8_t message[CT_MSG_LEN];
/* FNV-1a over every signature produced (outside the traced regions). The
 * deterministic hedging seed makes it a function of the arithmetic only, so
 * a mitigated build must print the same digest as the stock build. */
static uint32_t sig_digest = 0x811c9dc5U;

static void digest_signature(void)
{
	for (size_t i = 0U; i < sizeof(signature); ++i) {
		sig_digest ^= signature[i];
		sig_digest += (sig_digest << 1) + (sig_digest << 4) +
			      (sig_digest << 7) + (sig_digest << 8) +
			      (sig_digest << 24);
	}
}

/* The plugin reads the label from the first argument register (rdi). */
__attribute__((noinline)) void pqcp_ct_region_begin(uint32_t label)
{
	__asm__ volatile("" : : "r"(label) : "memory");
}

__attribute__((noinline)) void pqcp_ct_region_end(uint32_t label)
{
	__asm__ volatile("" : : "r"(label) : "memory");
}

/*
 * The plugin reads site, length and value class from the first three
 * argument registers (rdi, rsi, rdx on x86_64; r0..r2 on Cortex-M). 32-bit
 * arguments keep that true on both: a 64-bit argument would occupy a register
 * pair on 32-bit ARM. The plugin masks the registers to 32 bits.
 */
__attribute__((noinline)) void pqcp_ct_event(uint32_t site, uint32_t len,
					     uint32_t cls)
{
	__asm__ volatile("" : : "r"(site), "r"(len), "r"(cls) : "memory");
}

/*
 * Called from mldsa-native wherever it declassifies data. The value class is
 * the raw value for words up to 8 bytes (norm-check results) and an FNV-1a
 * digest for longer buffers, so equal declassified values give equal classes.
 */
__attribute__((noinline)) void pqcp_ct_declassify(const void *ptr, size_t len)
{
	const uint8_t *p = ptr;
	uint32_t cls = 0U;

	if (len <= 8U) {
		/* Raw value (norm-check flags), folded to 32 bits. */
		for (size_t i = 0U; i < len; ++i) {
			cls ^= (uint32_t)p[i] << (8U * (i & 3U));
		}
	} else {
		/* 32-bit FNV-1a. The multiply by the prime 0x01000193 is
		 * spelled as shifts and adds in 32-bit arithmetic so the
		 * harness contains no variable-latency multiplier on
		 * Cortex-M3 (a 64-bit shift would compile to UMULL). */
		cls = 0x811c9dc5U;
		for (size_t i = 0U; i < len; ++i) {
			cls ^= p[i];
			cls += (cls << 1) + (cls << 4) + (cls << 7) +
			       (cls << 8) + (cls << 24);
		}
	}
	pqcp_ct_event((uint32_t)(uintptr_t)__builtin_return_address(0),
		      (uint32_t)len, cls);
}

static uint32_t prng_state;

static uint32_t prng(void)
{
	prng_state ^= prng_state << 13;
	prng_state ^= prng_state >> 17;
	prng_state ^= prng_state << 5;
	return prng_state;
}

static void seed_for_message(uint32_t msg)
{
	uint8_t seed[32];

	memset(seed, 0, sizeof(seed));
	memcpy(seed, "PQCP-CT-TRACE-DSA", 17U);
	seed[20] = (uint8_t)msg;
	zassert_equal(pqcp_rng_deterministic_seed(seed, sizeof(seed)),
		      PQCP_RNG_SUCCESS);
}

/* Replace s1, s2, t0 with fresh in-range packed values; keep rho, K, tr. */
static void craft_secret(uint8_t *sk, uint32_t variant)
{
	prng_state = 0x9E3779B9U * (variant + 1U);
	for (size_t i = 0U; i < SK_S1_LEN + SK_S2_LEN; ++i) {
		/* eta - coefficient, each nibble in [0, 2*eta] = [0, 8] */
		sk[SK_S1_OFF + i] = (uint8_t)((prng() % 9U) |
					      ((prng() % 9U) << 4));
	}
	for (size_t i = 0U; i < SK_T0_LEN; ++i) {
		sk[SK_T0_OFF + i] = (uint8_t)prng();
	}
}

static void run_region(uint32_t label)
{
	const unsigned int irq = irq_lock();

	pqcp_ct_region_begin(label);
	(void)pqcp_mldsa_sign(PQCP_MLDSA_65, work_sk, message, sizeof(message),
			      NULL, 0U, signature);
	pqcp_ct_region_end(label);
	irq_unlock(irq);
}

ZTEST(pqcp_ct_trace_mldsa, test_sign_relational_trace_segments)
{
	uint8_t seed[32] = "PQCP-CT-TRACE-DSA-KEY";

	zassert_equal(pqcp_rng_deterministic_seed(seed, sizeof(seed)),
		      PQCP_RNG_SUCCESS);
	zassert_equal(pqcp_mldsa_keypair(PQCP_MLDSA_65, public_key, base_sk),
		      PQCP_MLDSA_SUCCESS);

	for (uint32_t m = 0U; m < CT_MSGS; ++m) {
		memset(message, 0, sizeof(message));
		memcpy(message, "ct-trace-dsa-message", 20U);
		message[24] = (uint8_t)m;

		for (uint32_t v = 0U; v < CT_VARIANTS; ++v) {
			memcpy(work_sk, base_sk, sizeof(work_sk));
			if (v > 0U) {
				craft_secret(work_sk, v);
			}
			seed_for_message(m); /* identical hedging randomness */
			run_region((m << 8) | v);
			digest_signature();
			if (v == 0U) {
				/* Sanity: the genuine key signs validly. */
				zassert_equal(pqcp_mldsa_verify(
						      PQCP_MLDSA_65, public_key,
						      message, sizeof(message),
						      NULL, 0U, signature),
					      PQCP_MLDSA_SUCCESS);
			}
		}
	}
	printk("PQCP_CT_SIGDIGEST 0x%08x signatures=%u\n", sig_digest,
	       CT_MSGS * CT_VARIANTS);
	printk("PQCP_CT_TRACE_APP alg=MLDSA-65 msgs=%u variants=%u\n", CT_MSGS,
	       CT_VARIANTS);
}

ZTEST_SUITE(pqcp_ct_trace_mldsa, NULL, NULL, NULL, NULL, NULL);
