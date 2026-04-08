/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Basic Signature Sample
 *
 * Demonstrates ML-DSA digital signatures using the PQCP module.
 * Runs keygen, signing, and verification operations.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>
#include <pqcp_zephyr/bench.h>

#include <string.h>

/* Test message */
static const uint8_t test_message[] = 
    "The quick brown fox jumps over the lazy dog. "
    "This is a test message for ML-DSA signature verification.";

/* Print hex bytes */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printk("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) {
        printk("%02x", data[i]);
    }
    if (len > 16) {
        printk("...");
    }
    printk("\n");
}

int main(void)
{
    printk("\n");
    printk("========================================\n");
    printk("  PQCP Basic ML-DSA Sample\n");
    printk("========================================\n\n");
    
    /* Initialize RNG */
    int ret = pqcp_rng_init();
    if (ret != 0) {
        printk("ERROR: Failed to initialize RNG: %d\n", ret);
        return -1;
    }
    printk("RNG initialized successfully\n");
    
    /* Test ML-DSA-65 (default) */
    pqcp_mldsa_level_t level = PQCP_MLDSA_65;
    
    printk("\nUsing %s\n", pqcp_mldsa_level_name(level));
    printk("  Public key size: %zu bytes\n", pqcp_mldsa_pk_size(level));
    printk("  Secret key size: %zu bytes\n", pqcp_mldsa_sk_size(level));
    printk("  Signature size:  %zu bytes\n\n", pqcp_mldsa_sig_size(level));
    
    printk("Message to sign (%zu bytes):\n  \"%s\"\n\n",
           sizeof(test_message) - 1, test_message);
    
    /* Allocate buffers */
    static uint8_t pk[PQCP_MLDSA_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLDSA_SK_SIZE_MAX];
    static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
    
    /* Initialize benchmark timing */
    pqcp_bench_init();
    
    /* Key Generation */
    printk("--- Key Generation ---\n");
    uint64_t start = pqcp_bench_start_timing();
    
    ret = pqcp_mldsa_keypair(level, pk, sk);
    
    uint64_t keygen_time = pqcp_bench_end_timing(start);
    
    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("ERROR: Key generation failed: %d\n", ret);
        return -1;
    }
    
    printk("Key generation completed\n");
    print_hex("Public key", pk, pqcp_mldsa_pk_size(level));
    printk("Time: %llu cycles\n\n", keygen_time);
    
    /* Signing */
    printk("--- Signing ---\n");
    start = pqcp_bench_start_timing();
    
    ret = pqcp_mldsa_sign(level, sk, 
                          test_message, sizeof(test_message) - 1,
                          NULL, 0,  /* No context */
                          sig);
    
    uint64_t sign_time = pqcp_bench_end_timing(start);
    
    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("ERROR: Signing failed: %d\n", ret);
        return -1;
    }
    
    printk("Signing completed\n");
    print_hex("Signature", sig, pqcp_mldsa_sig_size(level));
    printk("Time: %llu cycles\n\n", sign_time);
    
    /* Verification */
    printk("--- Verification ---\n");
    start = pqcp_bench_start_timing();
    
    ret = pqcp_mldsa_verify(level, pk,
                            test_message, sizeof(test_message) - 1,
                            NULL, 0,
                            sig);
    
    uint64_t verify_time = pqcp_bench_end_timing(start);
    
    if (ret == PQCP_MLDSA_SUCCESS) {
        printk("Signature verification: VALID\n");
    } else if (ret == PQCP_MLDSA_ERR_VERIFY) {
        printk("Signature verification: INVALID\n");
        return -1;
    } else {
        printk("ERROR: Verification failed: %d\n", ret);
        return -1;
    }
    printk("Time: %llu cycles\n\n", verify_time);
    
    /* Test with modified message (should fail) */
    printk("--- Negative Test (modified message) ---\n");
    uint8_t modified_msg[sizeof(test_message)];
    memcpy(modified_msg, test_message, sizeof(test_message));
    modified_msg[0] ^= 0x01;  /* Flip one bit */
    
    ret = pqcp_mldsa_verify(level, pk,
                            modified_msg, sizeof(modified_msg) - 1,
                            NULL, 0,
                            sig);
    
    if (ret == PQCP_MLDSA_ERR_VERIFY) {
        printk("Modified message correctly rejected!\n\n");
    } else {
        printk("WARNING: Modified message not rejected (ret=%d)\n\n", ret);
    }
    
    /* Test with context */
    printk("--- Signing with Context ---\n");
    const uint8_t ctx[] = "application-context";
    
    ret = pqcp_mldsa_sign(level, sk,
                          test_message, sizeof(test_message) - 1,
                          ctx, sizeof(ctx) - 1,
                          sig);
    
    if (ret == PQCP_MLDSA_SUCCESS) {
        printk("Signed with context: \"%s\"\n", ctx);
        
        ret = pqcp_mldsa_verify(level, pk,
                                test_message, sizeof(test_message) - 1,
                                ctx, sizeof(ctx) - 1,
                                sig);
        
        if (ret == PQCP_MLDSA_SUCCESS) {
            printk("Verification with context: VALID\n");
        } else {
            printk("Verification with context: INVALID\n");
        }
        
        /* Wrong context should fail */
        const uint8_t wrong_ctx[] = "wrong-context";
        ret = pqcp_mldsa_verify(level, pk,
                                test_message, sizeof(test_message) - 1,
                                wrong_ctx, sizeof(wrong_ctx) - 1,
                                sig);
        
        if (ret == PQCP_MLDSA_ERR_VERIFY) {
            printk("Wrong context correctly rejected!\n");
        }
    }
    
    /* Summary */
    printk("\n--- Summary ---\n");
    printk("Algorithm: %s\n", pqcp_mldsa_level_name(level));
    printk("KeyGen:    %llu cycles\n", keygen_time);
    printk("Sign:      %llu cycles\n", sign_time);
    printk("Verify:    %llu cycles\n", verify_time);
    printk("Total:     %llu cycles\n", keygen_time + sign_time + verify_time);
    
    /* Stack usage */
    uint32_t stack = pqcp_bench_get_stack_usage();
    if (stack > 0) {
        printk("Stack:     %u bytes\n", stack);
    }
    
    /* Emit structured metrics for parsing */
    printk("\n--- Structured Metrics ---\n");
    PQCP_LOG_CYCLES("primitive", "keygen", "MLDSA", level, keygen_time);
    PQCP_LOG_CYCLES("primitive", "sign", "MLDSA", level, sign_time);
    PQCP_LOG_CYCLES("primitive", "verify", "MLDSA", level, verify_time);
    
    if (stack > 0) {
        PQCP_LOG_STACK("primitive", "total", "MLDSA", level, stack);
    }
    
    PQCP_LOG_SIZE("primitive", "keygen", "MLDSA", level, "pk_size", pqcp_mldsa_pk_size(level));
    PQCP_LOG_SIZE("primitive", "keygen", "MLDSA", level, "sk_size", pqcp_mldsa_sk_size(level));
    PQCP_LOG_SIZE("primitive", "sign", "MLDSA", level, "sig_size", pqcp_mldsa_sig_size(level));
    PQCP_LOG_SIZE("primitive", "sign", "MLDSA", level, "msg_size", sizeof(test_message) - 1);
    
    PQCP_LOG_STATUS("primitive", "complete", "MLDSA", level, 1);
    
    printk("\n========================================\n");
    printk("  Sample completed successfully!\n");
    printk("========================================\n");
    
    return 0;
}
