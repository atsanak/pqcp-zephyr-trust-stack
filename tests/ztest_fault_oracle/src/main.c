/*
 * SPDX-License-Identifier: MIT
 *
 * Observation workload for the emulated fault campaign
 * (scripts/run_fault_campaign.py).
 *
 * The campaign patches instruction bytes of a COPY of this image (skip an
 * instruction, invert a branch) inside the ML-KEM decapsulation and ML-DSA
 * verify code, runs it, and judges the observations below by their
 * cryptographic meaning. The test makes no assertions about the values: the
 * golden run defines the expected observations and the campaign classifies
 * every deviation. Without faults this is a plain functional smoke test.
 *
 * Observation line (one per scenario, then a DONE line):
 *   PQCP_FAULT_OBS name=<scenario> rc=<int> out=<hex>
 *
 * Scenarios:
 *   KEM_VALID    decapsulate the genuine ciphertext      -> shared secret
 *   KEM_CORRUPT1 ciphertext with one flipped byte        -> rejection key
 *   KEM_CORRUPT2 ciphertext with another byte flipped    -> rejection key
 *   DSA_VALID    verify the genuine signature            -> accept
 *   DSA_BADSIG1  signature with one flipped byte         -> reject
 *   DSA_BADSIG2  signature with another byte flipped     -> reject
 *   DSA_BADMSG   genuine signature, different message    -> reject
 */

#include <stdint.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

static uint8_t kem_pk[PQCP_MLKEM_768_PK_SIZE];
static uint8_t kem_sk[PQCP_MLKEM_768_SK_SIZE];
static uint8_t kem_ct[PQCP_MLKEM_768_CT_SIZE];
static uint8_t kem_bad[PQCP_MLKEM_768_CT_SIZE];
static uint8_t kem_ss[PQCP_MLKEM_SS_SIZE];
static uint8_t kem_out[PQCP_MLKEM_SS_SIZE];

static uint8_t dsa_pk[PQCP_MLDSA_65_PK_SIZE];
static uint8_t dsa_sk[PQCP_MLDSA_65_SK_SIZE];
static uint8_t dsa_sig[PQCP_MLDSA_65_SIG_SIZE];
static uint8_t dsa_bad[PQCP_MLDSA_65_SIG_SIZE];

static const uint8_t message[32] = "PQCP fault campaign message #001";
static const uint8_t other_message[32] = "PQCP fault campaign message #002";

/*
 * Arm point for the fault campaign's post-boot and transient timing models
 * (scripts/fault_gdb.py): the campaign breaks here, applies its fault through
 * the QEMU debugger stub, and continues. Hit n precedes scenario n (1..7), so
 * everything before hit 1, including the boot self-test, runs fault-free.
 */
__attribute__((noinline)) void pqcp_fault_arm(uint32_t scenario)
{
	__asm__ volatile("" : : "r"(scenario) : "memory");
}

/*
 * Every call below reloads its arguments from volatile globals. A fault that
 * unwinds a callee's frame returns into this function with callee-saved
 * registers restored from the wrong stack slots; if the compiler kept the
 * ciphertext/signature pointer in one of those registers the NEXT scenario
 * would silently run on a different input and be misjudged. Reloading from
 * memory removes that harness artifact.
 */
static const uint8_t *volatile a_ct;
static const uint8_t *volatile a_kem_sk;
static uint8_t *volatile a_ss;
static const uint8_t *volatile a_dsa_pk;
static const uint8_t *volatile a_msg;
static const uint8_t *volatile a_sig;

static int decap(const uint8_t *ct)
{
	a_ct = ct;
	a_kem_sk = kem_sk;
	a_ss = kem_out;
	return pqcp_mlkem_decapsulate(PQCP_MLKEM_768, a_ct, a_kem_sk, a_ss);
}

static int verify(const uint8_t *msg, const uint8_t *sig)
{
	static const uint8_t none[1] = { 0 };

	a_dsa_pk = dsa_pk;
	a_msg = msg;
	a_sig = sig;
	return pqcp_mldsa_verify(PQCP_MLDSA_65, a_dsa_pk, a_msg,
				 sizeof(message), none, 0U, a_sig);
}

static void obs(const char *name, int rc, const uint8_t *out, size_t len)
{
	printk("PQCP_FAULT_OBS name=%s rc=%d out=", name, rc);
	for (size_t i = 0U; i < len; ++i) {
		printk("%02x", out[i]);
	}
	printk("\n");
}

ZTEST(pqcp_fault_oracle, test_observations)
{
	uint8_t seed64[64];
	uint8_t seed32[32];
	uint8_t coins[32];
	uint8_t none[1] = { 0 };
	int rc;

	memset(seed64, 0x5A, sizeof(seed64));
	memset(seed32, 0xA5, sizeof(seed32));
	memset(coins, 0x3C, sizeof(coins));

	/* ML-KEM-768 */
	zassert_equal(pqcp_mlkem_keypair_deterministic(
		PQCP_MLKEM_768, seed64, kem_pk, kem_sk), PQCP_MLKEM_SUCCESS);
	zassert_equal(pqcp_mlkem_encapsulate_deterministic(
		PQCP_MLKEM_768, kem_pk, coins, kem_ct, kem_ss),
		PQCP_MLKEM_SUCCESS);

	pqcp_fault_arm(1U);
	memset(kem_out, 0, sizeof(kem_out));
	rc = decap(kem_ct);
	obs("KEM_VALID", rc, kem_out, sizeof(kem_out));

	pqcp_fault_arm(2U);
	memcpy(kem_bad, kem_ct, sizeof(kem_bad));
	kem_bad[7] ^= 0x81U;
	memset(kem_out, 0, sizeof(kem_out));
	rc = decap(kem_bad);
	obs("KEM_CORRUPT1", rc, kem_out, sizeof(kem_out));

	pqcp_fault_arm(3U);
	memcpy(kem_bad, kem_ct, sizeof(kem_bad));
	kem_bad[sizeof(kem_bad) - 5U] ^= 0x42U;
	memset(kem_out, 0, sizeof(kem_out));
	rc = decap(kem_bad);
	obs("KEM_CORRUPT2", rc, kem_out, sizeof(kem_out));

	/* ML-DSA-65 */
	zassert_equal(pqcp_mldsa_keypair_deterministic(
		PQCP_MLDSA_65, seed32, dsa_pk, dsa_sk), PQCP_MLDSA_SUCCESS);
	zassert_equal(pqcp_rng_deterministic_seed(seed64, 32),
		      PQCP_RNG_SUCCESS);
	zassert_equal(pqcp_mldsa_sign(PQCP_MLDSA_65, dsa_sk, message,
				      sizeof(message), none, 0U, dsa_sig),
		      PQCP_MLDSA_SUCCESS);

	pqcp_fault_arm(4U);
	rc = verify(message, dsa_sig);
	obs("DSA_VALID", rc, none, 0U);

	pqcp_fault_arm(5U);
	memcpy(dsa_bad, dsa_sig, sizeof(dsa_bad));
	dsa_bad[11] ^= 0x01U;
	rc = verify(message, dsa_bad);
	obs("DSA_BADSIG1", rc, none, 0U);

	pqcp_fault_arm(6U);
	memcpy(dsa_bad, dsa_sig, sizeof(dsa_bad));
	dsa_bad[sizeof(dsa_bad) - 40U] ^= 0x80U;
	rc = verify(message, dsa_bad);
	obs("DSA_BADSIG2", rc, none, 0U);

	pqcp_fault_arm(7U);
	rc = verify(other_message, dsa_sig);
	obs("DSA_BADMSG", rc, none, 0U);

	printk("PQCP_FAULT_DONE\n");
}

ZTEST_SUITE(pqcp_fault_oracle, NULL, NULL, NULL, NULL, NULL);
