/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Primitive Tests
 *
 * Zephyr ztest suite for ML-KEM and ML-DSA operations.
 */

#include <zephyr/ztest.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

/* Static buffers for tests */
static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
static uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
static uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
static uint8_t ss1[PQCP_MLKEM_SS_SIZE];
static uint8_t ss2[PQCP_MLKEM_SS_SIZE];

static uint8_t sig_pk[PQCP_MLDSA_PK_SIZE_MAX];
static uint8_t sig_sk[PQCP_MLDSA_SK_SIZE_MAX];
static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];

static const uint8_t test_msg[] = "Test message for signature";

/*
 * ML-KEM Tests
 */

ZTEST(pqcp_primitive, test_mlkem_size_functions)
{
    /* Test size functions return expected values */
    zassert_equal(pqcp_mlkem_pk_size(PQCP_MLKEM_512), PQCP_MLKEM_512_PK_SIZE);
    zassert_equal(pqcp_mlkem_sk_size(PQCP_MLKEM_512), PQCP_MLKEM_512_SK_SIZE);
    zassert_equal(pqcp_mlkem_ct_size(PQCP_MLKEM_512), PQCP_MLKEM_512_CT_SIZE);
    
    zassert_equal(pqcp_mlkem_pk_size(PQCP_MLKEM_768), PQCP_MLKEM_768_PK_SIZE);
    zassert_equal(pqcp_mlkem_sk_size(PQCP_MLKEM_768), PQCP_MLKEM_768_SK_SIZE);
    zassert_equal(pqcp_mlkem_ct_size(PQCP_MLKEM_768), PQCP_MLKEM_768_CT_SIZE);
    
    zassert_equal(pqcp_mlkem_pk_size(PQCP_MLKEM_1024), PQCP_MLKEM_1024_PK_SIZE);
    zassert_equal(pqcp_mlkem_sk_size(PQCP_MLKEM_1024), PQCP_MLKEM_1024_SK_SIZE);
    zassert_equal(pqcp_mlkem_ct_size(PQCP_MLKEM_1024), PQCP_MLKEM_1024_CT_SIZE);
    
    /* Invalid level returns 0 */
    zassert_equal(pqcp_mlkem_pk_size(0), 0);
    zassert_equal(pqcp_mlkem_sk_size(999), 0);
}

ZTEST(pqcp_primitive, test_mlkem_level_names)
{
    zassert_str_equal(pqcp_mlkem_level_name(PQCP_MLKEM_512), "ML-KEM-512");
    zassert_str_equal(pqcp_mlkem_level_name(PQCP_MLKEM_768), "ML-KEM-768");
    zassert_str_equal(pqcp_mlkem_level_name(PQCP_MLKEM_1024), "ML-KEM-1024");
    zassert_str_equal(pqcp_mlkem_level_name(0), "Unknown");
}

ZTEST(pqcp_primitive, test_mlkem_keypair_null_args)
{
    int ret = pqcp_mlkem_keypair(PQCP_MLKEM_768, NULL, sk);
    zassert_equal(ret, PQCP_MLKEM_ERR_INVALID_ARG);
    
    ret = pqcp_mlkem_keypair(PQCP_MLKEM_768, pk, NULL);
    zassert_equal(ret, PQCP_MLKEM_ERR_INVALID_ARG);
}

ZTEST(pqcp_primitive, test_mlkem_keypair_success)
{
    int ret = pqcp_mlkem_keypair(PQCP_MLKEM_768, pk, sk);
    zassert_equal(ret, PQCP_MLKEM_SUCCESS, "Keypair generation failed: %d", ret);
    
    /* Keys should not be all zeros */
    bool pk_nonzero = false;
    for (size_t i = 0; i < pqcp_mlkem_pk_size(PQCP_MLKEM_768); i++) {
        if (pk[i] != 0) {
            pk_nonzero = true;
            break;
        }
    }
    zassert_true(pk_nonzero, "Public key is all zeros");
}

ZTEST(pqcp_primitive, test_mlkem_encaps_decaps)
{
    /* Generate keypair */
    int ret = pqcp_mlkem_keypair(PQCP_MLKEM_768, pk, sk);
    zassert_equal(ret, PQCP_MLKEM_SUCCESS);
    
    /* Encapsulate */
    ret = pqcp_mlkem_encapsulate(PQCP_MLKEM_768, pk, ct, ss1);
    zassert_equal(ret, PQCP_MLKEM_SUCCESS, "Encapsulation failed: %d", ret);
    
    /* Decapsulate */
    ret = pqcp_mlkem_decapsulate(PQCP_MLKEM_768, ct, sk, ss2);
    zassert_equal(ret, PQCP_MLKEM_SUCCESS, "Decapsulation failed: %d", ret);
    
    /* Shared secrets must match */
    zassert_mem_equal(ss1, ss2, PQCP_MLKEM_SS_SIZE,
                      "Shared secrets don't match");
}

ZTEST(pqcp_primitive, test_mlkem_encaps_null_args)
{
    int ret = pqcp_mlkem_encapsulate(PQCP_MLKEM_768, NULL, ct, ss1);
    zassert_equal(ret, PQCP_MLKEM_ERR_INVALID_ARG);
    
    ret = pqcp_mlkem_encapsulate(PQCP_MLKEM_768, pk, NULL, ss1);
    zassert_equal(ret, PQCP_MLKEM_ERR_INVALID_ARG);
    
    ret = pqcp_mlkem_encapsulate(PQCP_MLKEM_768, pk, ct, NULL);
    zassert_equal(ret, PQCP_MLKEM_ERR_INVALID_ARG);
}

/*
 * ML-DSA Tests
 */

ZTEST(pqcp_primitive, test_mldsa_size_functions)
{
    zassert_equal(pqcp_mldsa_pk_size(PQCP_MLDSA_44), PQCP_MLDSA_44_PK_SIZE);
    zassert_equal(pqcp_mldsa_sk_size(PQCP_MLDSA_44), PQCP_MLDSA_44_SK_SIZE);
    zassert_equal(pqcp_mldsa_sig_size(PQCP_MLDSA_44), PQCP_MLDSA_44_SIG_SIZE);
    
    zassert_equal(pqcp_mldsa_pk_size(PQCP_MLDSA_65), PQCP_MLDSA_65_PK_SIZE);
    zassert_equal(pqcp_mldsa_sk_size(PQCP_MLDSA_65), PQCP_MLDSA_65_SK_SIZE);
    zassert_equal(pqcp_mldsa_sig_size(PQCP_MLDSA_65), PQCP_MLDSA_65_SIG_SIZE);
    
    zassert_equal(pqcp_mldsa_pk_size(PQCP_MLDSA_87), PQCP_MLDSA_87_PK_SIZE);
    
    /* Invalid returns 0 */
    zassert_equal(pqcp_mldsa_pk_size(0), 0);
}

ZTEST(pqcp_primitive, test_mldsa_level_names)
{
    zassert_str_equal(pqcp_mldsa_level_name(PQCP_MLDSA_44), "ML-DSA-44");
    zassert_str_equal(pqcp_mldsa_level_name(PQCP_MLDSA_65), "ML-DSA-65");
    zassert_str_equal(pqcp_mldsa_level_name(PQCP_MLDSA_87), "ML-DSA-87");
}

ZTEST(pqcp_primitive, test_mldsa_keypair_success)
{
    int ret = pqcp_mldsa_keypair(PQCP_MLDSA_65, sig_pk, sig_sk);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS, "Keypair generation failed: %d", ret);
}

ZTEST(pqcp_primitive, test_mldsa_sign_verify)
{
    /* Generate keypair */
    int ret = pqcp_mldsa_keypair(PQCP_MLDSA_65, sig_pk, sig_sk);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);
    
    /* Sign */
    ret = pqcp_mldsa_sign(PQCP_MLDSA_65, sig_sk,
                          test_msg, sizeof(test_msg) - 1,
                          NULL, 0, sig);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS, "Signing failed: %d", ret);
    
    /* Verify */
    ret = pqcp_mldsa_verify(PQCP_MLDSA_65, sig_pk,
                            test_msg, sizeof(test_msg) - 1,
                            NULL, 0, sig);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS, "Verification failed: %d", ret);
}

ZTEST(pqcp_primitive, test_mldsa_verify_modified_message)
{
    /* Generate keypair and sign */
    int ret = pqcp_mldsa_keypair(PQCP_MLDSA_65, sig_pk, sig_sk);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);
    
    ret = pqcp_mldsa_sign(PQCP_MLDSA_65, sig_sk,
                          test_msg, sizeof(test_msg) - 1,
                          NULL, 0, sig);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);
    
    /* Modify message */
    uint8_t modified_msg[sizeof(test_msg)];
    memcpy(modified_msg, test_msg, sizeof(test_msg));
    modified_msg[0] ^= 0x01;
    
    /* Verification should fail */
    ret = pqcp_mldsa_verify(PQCP_MLDSA_65, sig_pk,
                            modified_msg, sizeof(modified_msg) - 1,
                            NULL, 0, sig);
    zassert_equal(ret, PQCP_MLDSA_ERR_VERIFY,
                  "Modified message should not verify");
}

ZTEST(pqcp_primitive, test_mldsa_context_string)
{
    const uint8_t ctx[] = "test-context";
    
    /* Generate keypair */
    int ret = pqcp_mldsa_keypair(PQCP_MLDSA_65, sig_pk, sig_sk);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);
    
    /* Sign with context */
    ret = pqcp_mldsa_sign(PQCP_MLDSA_65, sig_sk,
                          test_msg, sizeof(test_msg) - 1,
                          ctx, sizeof(ctx) - 1, sig);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);
    
    /* Verify with same context should succeed */
    ret = pqcp_mldsa_verify(PQCP_MLDSA_65, sig_pk,
                            test_msg, sizeof(test_msg) - 1,
                            ctx, sizeof(ctx) - 1, sig);
    zassert_equal(ret, PQCP_MLDSA_SUCCESS);
    
    /* Verify with different context should fail */
    const uint8_t wrong_ctx[] = "wrong-context";
    ret = pqcp_mldsa_verify(PQCP_MLDSA_65, sig_pk,
                            test_msg, sizeof(test_msg) - 1,
                            wrong_ctx, sizeof(wrong_ctx) - 1, sig);
    zassert_equal(ret, PQCP_MLDSA_ERR_VERIFY,
                  "Wrong context should not verify");
}

ZTEST(pqcp_primitive, test_mldsa_context_too_long)
{
    /* Context > 255 bytes should fail */
    uint8_t long_ctx[300];
    memset(long_ctx, 'X', sizeof(long_ctx));
    
    int ret = pqcp_mldsa_sign(PQCP_MLDSA_65, sig_sk,
                              test_msg, sizeof(test_msg) - 1,
                              long_ctx, sizeof(long_ctx), sig);
    zassert_equal(ret, PQCP_MLDSA_ERR_CONTEXT_LEN,
                  "Should reject context > 255 bytes");
}

/*
 * Test Suite Setup
 */

static void *pqcp_primitive_setup(void)
{
    /* Initialize RNG before tests */
    int ret = pqcp_rng_init();
    zassert_equal(ret, 0, "RNG init failed");
    
    return NULL;
}

ZTEST_SUITE(pqcp_primitive, NULL, pqcp_primitive_setup, NULL, NULL, NULL);
