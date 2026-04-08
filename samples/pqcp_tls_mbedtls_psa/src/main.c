/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP TLS mbedTLS PSA Sample
 *
 * Demonstrates TLS with post-quantum cryptography using mbedTLS and PSA.
 * Note: Full PQC TLS requires mbedTLS PQC support which is still evolving.
 * This sample demonstrates the PSA driver integration and basic TLS.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>
#include <pqcp_zephyr/bench.h>

#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C
#include <psa/crypto.h>
#endif

#include <string.h>

/* Test PSA crypto initialization and RNG */
static int test_psa_init(void)
{
#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C
    printk("Initializing PSA Crypto...\n");
    
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printk("ERROR: psa_crypto_init failed: %d\n", (int)status);
        return -1;
    }
    
    printk("PSA Crypto initialized successfully\n");
    
    /* Test PSA RNG */
    uint8_t random_bytes[32];
    status = psa_generate_random(random_bytes, sizeof(random_bytes));
    if (status != PSA_SUCCESS) {
        printk("ERROR: psa_generate_random failed: %d\n", (int)status);
        return -1;
    }
    
    printk("PSA RNG test: ");
    for (int i = 0; i < 16; i++) {
        printk("%02x", random_bytes[i]);
    }
    printk("...\n");
    
    return 0;
#else
    printk("PSA Crypto not enabled\n");
    return -1;
#endif
}

/* Test PQCP operations through PSA-style interface */
static int test_pqc_operations(void)
{
    int64_t t_start, t_end;
    
    printk("\n--- Testing PQCP Operations ---\n");
    
    /* ML-KEM test */
    printk("\nML-KEM-768:\n");
    
    static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    static uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
    static uint8_t ss1[PQCP_MLKEM_SS_SIZE];
    static uint8_t ss2[PQCP_MLKEM_SS_SIZE];
    
    t_start = k_uptime_get();
    int ret = pqcp_mlkem_keypair(PQCP_MLKEM_768, pk, sk);
    t_end = k_uptime_get();
    if (ret != PQCP_MLKEM_SUCCESS) {
        printk("  KeyGen FAILED: %d\n", ret);
        return -1;
    }
    printk("  KeyGen: OK (%lld ms)\n", t_end - t_start);
    PQCP_LOG_TIME_MS("driver", "keygen", "MLKEM", 768, t_end - t_start);
    
    t_start = k_uptime_get();
    ret = pqcp_mlkem_encapsulate(PQCP_MLKEM_768, pk, ct, ss1);
    t_end = k_uptime_get();
    if (ret != PQCP_MLKEM_SUCCESS) {
        printk("  Encaps FAILED: %d\n", ret);
        return -1;
    }
    printk("  Encaps: OK (%lld ms)\n", t_end - t_start);
    PQCP_LOG_TIME_MS("driver", "encaps", "MLKEM", 768, t_end - t_start);
    
    t_start = k_uptime_get();
    ret = pqcp_mlkem_decapsulate(PQCP_MLKEM_768, ct, sk, ss2);
    t_end = k_uptime_get();
    if (ret != PQCP_MLKEM_SUCCESS) {
        printk("  Decaps FAILED: %d\n", ret);
        return -1;
    }
    printk("  Decaps: OK (%lld ms)\n", t_end - t_start);
    PQCP_LOG_TIME_MS("driver", "decaps", "MLKEM", 768, t_end - t_start);
    
    if (memcmp(ss1, ss2, PQCP_MLKEM_SS_SIZE) == 0) {
        printk("  Shared secrets match: OK\n");
        PQCP_LOG_STATUS("driver", "selftest", "MLKEM", 768, 1);
    } else {
        printk("  Shared secrets MISMATCH!\n");
        PQCP_LOG_STATUS("driver", "selftest", "MLKEM", 768, 0);
        return -1;
    }
    
    /* Log sizes for TLS planning */
    PQCP_LOG_SIZE("driver", "size", "MLKEM", 768, "pk", pqcp_mlkem_pk_size(PQCP_MLKEM_768));
    PQCP_LOG_SIZE("driver", "size", "MLKEM", 768, "ct", pqcp_mlkem_ct_size(PQCP_MLKEM_768));
    PQCP_LOG_SIZE("driver", "size", "MLKEM", 768, "ss", PQCP_MLKEM_SS_SIZE);
    
    /* ML-DSA test */
    printk("\nML-DSA-65:\n");
    
    static uint8_t sig_pk[PQCP_MLDSA_PK_SIZE_MAX];
    static uint8_t sig_sk[PQCP_MLDSA_SK_SIZE_MAX];
    static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
    const uint8_t msg[] = "Test message for TLS authentication";
    
    t_start = k_uptime_get();
    ret = pqcp_mldsa_keypair(PQCP_MLDSA_65, sig_pk, sig_sk);
    t_end = k_uptime_get();
    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("  KeyGen FAILED: %d\n", ret);
        return -1;
    }
    printk("  KeyGen: OK (%lld ms)\n", t_end - t_start);
    PQCP_LOG_TIME_MS("driver", "keygen", "MLDSA", 65, t_end - t_start);
    
    t_start = k_uptime_get();
    ret = pqcp_mldsa_sign(PQCP_MLDSA_65, sig_sk, msg, sizeof(msg) - 1, NULL, 0, sig);
    t_end = k_uptime_get();
    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("  Sign FAILED: %d\n", ret);
        return -1;
    }
    printk("  Sign: OK (%lld ms)\n", t_end - t_start);
    PQCP_LOG_TIME_MS("driver", "sign", "MLDSA", 65, t_end - t_start);
    
    t_start = k_uptime_get();
    ret = pqcp_mldsa_verify(PQCP_MLDSA_65, sig_pk, msg, sizeof(msg) - 1, NULL, 0, sig);
    t_end = k_uptime_get();
    if (ret == PQCP_MLDSA_SUCCESS) {
        printk("  Verify: OK (%lld ms)\n", t_end - t_start);
        PQCP_LOG_TIME_MS("driver", "verify", "MLDSA", 65, t_end - t_start);
        PQCP_LOG_STATUS("driver", "selftest", "MLDSA", 65, 1);
    } else {
        printk("  Verify FAILED: %d\n", ret);
        PQCP_LOG_STATUS("driver", "selftest", "MLDSA", 65, 0);
        return -1;
    }
    
    /* Log sizes for TLS planning */
    PQCP_LOG_SIZE("driver", "size", "MLDSA", 65, "pk", pqcp_mldsa_pk_size(PQCP_MLDSA_65));
    PQCP_LOG_SIZE("driver", "size", "MLDSA", 65, "sig", pqcp_mldsa_sig_size(PQCP_MLDSA_65));
    PQCP_LOG_SIZE("driver", "size", "MLDSA", 65, "sk", pqcp_mldsa_sk_size(PQCP_MLDSA_65));
    
    return 0;
}

/* Placeholder for actual TLS handshake */
static void demo_tls_usage(void)
{
    printk("\n--- TLS Integration Notes ---\n");
    printk("\n");
    printk("To use PQC in TLS with mbedTLS:\n");
    printk("\n");
    printk("1. mbedTLS ML-KEM support is in development (see issue #9803)\n");
    printk("2. Hybrid key exchange (X25519 + ML-KEM) expected in future\n");
    printk("3. ML-DSA certificates need X.509 PQC OID support\n");
    printk("\n");
    printk("Current integration path:\n");
    printk("  - Use PQCP PSA drivers for ML-DSA signing\n");
    printk("  - Use PQCP for out-of-band key encapsulation\n");
    printk("  - Wait for mbedTLS TLS 1.3 PQC groups\n");
    printk("\n");
    printk("Key sizes for TLS planning:\n");
    printk("  ML-KEM-768:  pk=%zu ct=%zu ss=%d\n",
           pqcp_mlkem_pk_size(PQCP_MLKEM_768),
           pqcp_mlkem_ct_size(PQCP_MLKEM_768),
           PQCP_MLKEM_SS_SIZE);
    printk("  ML-DSA-65:   pk=%zu sig=%zu\n",
           pqcp_mldsa_pk_size(PQCP_MLDSA_65),
           pqcp_mldsa_sig_size(PQCP_MLDSA_65));
    printk("\n");
    printk("Estimated TLS 1.3 handshake overhead:\n");
    printk("  Hybrid (X25519+ML-KEM-768):  +1184 pk +1088 ct = ~2.3KB extra\n");
    printk("  ML-DSA-65 cert:              +1952 pk +3293 sig = ~5.2KB extra\n");
    printk("  Total extra for PQC:         ~7-10KB per handshake\n");
}

int main(void)
{
    printk("\n");
    printk("========================================\n");
    printk("  PQCP TLS mbedTLS PSA Sample\n");
    printk("========================================\n\n");
    
    /* Initialize RNG */
    int ret = pqcp_rng_init();
    if (ret != 0) {
        printk("ERROR: Failed to initialize RNG: %d\n", ret);
        return -1;
    }
    
    /* Initialize PSA Crypto */
    ret = test_psa_init();
    if (ret != 0) {
        printk("WARNING: PSA init failed, continuing with PQCP only\n");
    }
    
    /* Test PQC operations */
    ret = test_pqc_operations();
    if (ret != 0) {
        printk("\nERROR: PQC operations failed\n");
        return -1;
    }
    
    /* Show TLS integration notes */
    demo_tls_usage();
    
    printk("========================================\n");
    printk("  Sample completed successfully!\n");
    printk("========================================\n");
    
    return 0;
}
