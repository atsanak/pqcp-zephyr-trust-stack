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

enum {
    MLKEM_DERAND_COINS_BYTES = 64,
    MLKEM_ENCAPS_MESSAGE_BYTES = 32,
    MLDSA_SIGN_MESSAGE_BYTES = 84,
    MLDSA_SIGN_CONTEXT_BYTES = 24,
    MLDSA_VERIFY_MESSAGE_BYTES = 2793,
    MLDSA_VERIFY_CONTEXT_BYTES = 183,
};

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

static void build_mldsa_external_preamble(const uint8_t *context, size_t context_len,
                                          uint8_t *preamble, size_t *preamble_len)
{
    zassert_not_null(preamble);
    zassert_not_null(preamble_len);
    zassert_true(context_len <= UINT8_MAX, "context too large for external preamble");

    preamble[0] = 0U;
    preamble[1] = (uint8_t)context_len;
    if ((context != NULL) && (context_len > 0U)) {
        memcpy(&preamble[2], context, context_len);
    }
    *preamble_len = context_len + 2U;
}

ZTEST(pqcp_acvp_kat, test_mlkem768_keygen_kat)
{
    uint8_t keypair_coins[MLKEM_DERAND_COINS_BYTES];
    uint8_t expected_pk[PQCP_MLKEM_768_PK_SIZE];
    uint8_t expected_sk[PQCP_MLKEM_768_SK_SIZE];
    uint8_t pk[PQCP_MLKEM_768_PK_SIZE];
    uint8_t sk[PQCP_MLKEM_768_SK_SIZE];

    decode_hex_exact(MLKEM768_KEYGEN_D_HEX, keypair_coins, PQCP_MLKEM_SS_SIZE);
    decode_hex_exact(MLKEM768_KEYGEN_Z_HEX, keypair_coins + PQCP_MLKEM_SS_SIZE,
                     PQCP_MLKEM_SS_SIZE);
    decode_hex_exact(MLKEM768_KEYGEN_PK_HEX, expected_pk, sizeof(expected_pk));
    decode_hex_exact(MLKEM768_KEYGEN_SK_HEX, expected_sk, sizeof(expected_sk));

    zassert_equal(crypto_kem_keypair_derand(pk, sk, keypair_coins), 0);
    zassert_mem_equal(pk, expected_pk, sizeof(pk), "ML-KEM-768 public key KAT mismatch");
    zassert_mem_equal(sk, expected_sk, sizeof(sk), "ML-KEM-768 secret key KAT mismatch");
}

ZTEST(pqcp_acvp_kat, test_mlkem768_encaps_and_decaps_kat)
{
    uint8_t encaps_message[MLKEM_ENCAPS_MESSAGE_BYTES];
    uint8_t pk[PQCP_MLKEM_768_PK_SIZE];
    uint8_t sk[PQCP_MLKEM_768_SK_SIZE];
    uint8_t expected_ct[PQCP_MLKEM_768_CT_SIZE];
    uint8_t expected_ss[PQCP_MLKEM_SS_SIZE];
    uint8_t ct[PQCP_MLKEM_768_CT_SIZE];
    uint8_t ss[PQCP_MLKEM_SS_SIZE];
    uint8_t recovered_ss[PQCP_MLKEM_SS_SIZE];

    decode_hex_exact(MLKEM768_ENCAPS_PK_HEX, pk, sizeof(pk));
    decode_hex_exact(MLKEM768_ENCAPS_SK_HEX, sk, sizeof(sk));
    decode_hex_exact(MLKEM768_ENCAPS_MESSAGE_HEX, encaps_message, sizeof(encaps_message));
    decode_hex_exact(MLKEM768_ENCAPS_CT_HEX, expected_ct, sizeof(expected_ct));
    decode_hex_exact(MLKEM768_ENCAPS_SS_HEX, expected_ss, sizeof(expected_ss));

    zassert_equal(crypto_kem_enc_derand(ct, ss, pk, encaps_message), 0);
    zassert_mem_equal(ct, expected_ct, sizeof(ct), "ML-KEM-768 ciphertext KAT mismatch");
    zassert_mem_equal(ss, expected_ss, sizeof(ss), "ML-KEM-768 shared secret KAT mismatch");

    zassert_equal(
        pqcp_mlkem_decapsulate(PQCP_MLKEM_768, ct, sk, recovered_ss),
        PQCP_MLKEM_SUCCESS
    );
    zassert_mem_equal(recovered_ss, expected_ss, sizeof(recovered_ss),
                      "ML-KEM-768 decapsulation mismatch");
}

ZTEST(pqcp_acvp_kat, test_mldsa65_sign_kat)
{
    uint8_t message[MLDSA_SIGN_MESSAGE_BYTES];
    uint8_t context[MLDSA_SIGN_CONTEXT_BYTES];
    uint8_t preamble[MLDSA_SIGN_CONTEXT_BYTES + 2U];
    size_t preamble_len = 0U;
    uint8_t sk[PQCP_MLDSA_65_SK_SIZE];
    uint8_t expected_sig[PQCP_MLDSA_65_SIG_SIZE];
    uint8_t sig[PQCP_MLDSA_65_SIG_SIZE];
    uint8_t deterministic_rnd[32] = { 0U };
    size_t sig_len = 0U;

    decode_hex_exact(MLDSA65_SIGN_MESSAGE_HEX, message, sizeof(message));
    decode_hex_exact(MLDSA65_SIGN_CONTEXT_HEX, context, sizeof(context));
    decode_hex_exact(MLDSA65_SIGN_SK_HEX, sk, sizeof(sk));
    decode_hex_exact(MLDSA65_SIGN_SIG_HEX, expected_sig, sizeof(expected_sig));
    build_mldsa_external_preamble(context, sizeof(context), preamble, &preamble_len);

    zassert_equal(crypto_sign_signature_internal(sig, &sig_len,
                                                 message, sizeof(message),
                                                 preamble, preamble_len,
                                                 deterministic_rnd, sk, 0),
                  0);
    zassert_equal(sig_len, sizeof(sig), "unexpected ML-DSA-65 signature length");
    zassert_mem_equal(sig, expected_sig, sizeof(sig), "ML-DSA-65 signature KAT mismatch");
}

ZTEST(pqcp_acvp_kat, test_mldsa65_verify_kat)
{
    uint8_t pk[PQCP_MLDSA_65_PK_SIZE];
    uint8_t message[MLDSA_VERIFY_MESSAGE_BYTES];
    uint8_t context[MLDSA_VERIFY_CONTEXT_BYTES];
    uint8_t sig[PQCP_MLDSA_65_SIG_SIZE];

    decode_hex_exact(MLDSA65_VERIFY_PK_HEX, pk, sizeof(pk));
    decode_hex_exact(MLDSA65_VERIFY_MESSAGE_HEX, message, sizeof(message));
    decode_hex_exact(MLDSA65_VERIFY_CONTEXT_HEX, context, sizeof(context));
    decode_hex_exact(MLDSA65_VERIFY_SIG_HEX, sig, sizeof(sig));

    zassert_equal(pqcp_mldsa_verify(PQCP_MLDSA_65, pk, message, sizeof(message),
                                    context, sizeof(context), sig),
                  PQCP_MLDSA_SUCCESS);
}

ZTEST_SUITE(pqcp_acvp_kat, NULL, NULL, NULL, NULL, NULL);
