/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP ACVP known-answer smoke tests.
 */

#include <zephyr/ztest.h>

#include <pqcp_zephyr/acvp_cmd.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/mlkem.h>

#include <string.h>

#include "kat_vectors.h"
#include "mlkem_native.h"
#ifdef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_SECRETKEYBYTES
#endif
#ifdef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#endif
#ifdef CRYPTO_BYTES
#undef CRYPTO_BYTES
#endif
#include "mldsa_native.h"

/*
 * mldsa-native exports the namespaced internal symbols directly; mirror the
 * upstream KAT generator aliases so the test stays level-agnostic.
 */
#define crypto_sign_keypair_internal MLD_API_NAMESPACE(keypair_internal)
#define crypto_sign_signature_internal MLD_API_NAMESPACE(signature_internal)

static void decode_hex_exact(const char *hex, uint8_t *out, size_t expected_len)
{
    size_t out_len = 0U;

    zassert_equal(
        pqcp_acvp_hex_to_bytes(hex, out, &out_len, expected_len),
        0,
        "hex decode failed"
    );
    zassert_equal(out_len, expected_len, "unexpected decoded length");
}

ZTEST(pqcp_acvp_kat, test_mlkem768_keygen_and_encaps_kat)
{
    uint8_t keypair_coins[64];
    uint8_t encaps_coins[32];
    uint8_t expected_pk[PQCP_MLKEM_768_PK_SIZE];
    uint8_t expected_sk[PQCP_MLKEM_768_SK_SIZE];
    uint8_t expected_ct[PQCP_MLKEM_768_CT_SIZE];
    uint8_t expected_ss[PQCP_MLKEM_SS_SIZE];
    uint8_t pk[PQCP_MLKEM_768_PK_SIZE];
    uint8_t sk[PQCP_MLKEM_768_SK_SIZE];
    uint8_t ct[PQCP_MLKEM_768_CT_SIZE];
    uint8_t ss[PQCP_MLKEM_SS_SIZE];
    uint8_t recovered_ss[PQCP_MLKEM_SS_SIZE];

    decode_hex_exact(MLKEM768_KEYPAIR_COINS_HEX, keypair_coins, sizeof(keypair_coins));
    decode_hex_exact(MLKEM768_ENCAPS_COINS_HEX, encaps_coins, sizeof(encaps_coins));
    decode_hex_exact(MLKEM768_PK_HEX, expected_pk, sizeof(expected_pk));
    decode_hex_exact(MLKEM768_SK_HEX, expected_sk, sizeof(expected_sk));
    decode_hex_exact(MLKEM768_CT_HEX, expected_ct, sizeof(expected_ct));
    decode_hex_exact(MLKEM768_SS_HEX, expected_ss, sizeof(expected_ss));

    zassert_equal(crypto_kem_keypair_derand(pk, sk, keypair_coins), 0);
    zassert_mem_equal(pk, expected_pk, sizeof(pk), "ML-KEM-768 public key KAT mismatch");
    zassert_mem_equal(sk, expected_sk, sizeof(sk), "ML-KEM-768 secret key KAT mismatch");

    zassert_equal(crypto_kem_enc_derand(ct, ss, pk, encaps_coins), 0);
    zassert_mem_equal(ct, expected_ct, sizeof(ct), "ML-KEM-768 ciphertext KAT mismatch");
    zassert_mem_equal(ss, expected_ss, sizeof(ss), "ML-KEM-768 shared secret KAT mismatch");

    zassert_equal(
        pqcp_mlkem_decapsulate(PQCP_MLKEM_768, ct, sk, recovered_ss),
        PQCP_MLKEM_SUCCESS
    );
    zassert_mem_equal(recovered_ss, expected_ss, sizeof(recovered_ss),
                      "ML-KEM-768 decapsulation mismatch");
}

ZTEST(pqcp_acvp_kat, test_mldsa65_sign_and_verify_kat)
{
    static const uint8_t preamble[] = { 0U, 0U };
    static const uint8_t empty_message[] = { 0U };
    uint8_t keypair_seed[32];
    uint8_t sign_rnd[32];
    uint8_t expected_pk[PQCP_MLDSA_65_PK_SIZE];
    uint8_t expected_sk[PQCP_MLDSA_65_SK_SIZE];
    uint8_t expected_sig[PQCP_MLDSA_65_SIG_SIZE];
    uint8_t pk[PQCP_MLDSA_65_PK_SIZE];
    uint8_t sk[PQCP_MLDSA_65_SK_SIZE];
    uint8_t sig[PQCP_MLDSA_65_SIG_SIZE];
    size_t sig_len = 0U;

    decode_hex_exact(MLDSA65_KEYPAIR_SEED_HEX, keypair_seed, sizeof(keypair_seed));
    decode_hex_exact(MLDSA65_SIGN_RND_HEX, sign_rnd, sizeof(sign_rnd));
    decode_hex_exact(MLDSA65_PK_HEX, expected_pk, sizeof(expected_pk));
    decode_hex_exact(MLDSA65_SK_HEX, expected_sk, sizeof(expected_sk));
    decode_hex_exact(MLDSA65_SIG_HEX, expected_sig, sizeof(expected_sig));

    zassert_equal(crypto_sign_keypair_internal(pk, sk, keypair_seed), 0);
    zassert_mem_equal(pk, expected_pk, sizeof(pk), "ML-DSA-65 public key KAT mismatch");
    zassert_mem_equal(sk, expected_sk, sizeof(sk), "ML-DSA-65 secret key KAT mismatch");

    zassert_equal(
        crypto_sign_signature_internal(sig, &sig_len,
                                       empty_message, 0U,
                                       preamble, sizeof(preamble),
                                       sign_rnd, sk, 0),
        0
    );
    zassert_equal(sig_len, sizeof(sig), "unexpected ML-DSA-65 signature length");
    zassert_mem_equal(sig, expected_sig, sizeof(sig), "ML-DSA-65 signature KAT mismatch");

    zassert_equal(
        pqcp_mldsa_verify(PQCP_MLDSA_65, pk, empty_message, 0U, NULL, 0U, sig),
        PQCP_MLDSA_SUCCESS
    );
}

ZTEST_SUITE(pqcp_acvp_kat, NULL, NULL, NULL, NULL, NULL);
