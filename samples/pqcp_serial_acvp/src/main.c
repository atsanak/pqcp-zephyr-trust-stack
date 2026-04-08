/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Serial ACVP Sample
 *
 * UART/Serial interface for running ACVP test vectors.
 * Accepts commands via serial and returns results for ACVP validation.
 *
 * Protocol:
 *   Input:  CMD:ALG:LEVEL:HEX_DATA
 *   Output: RESULT:HEX_DATA or ERROR:MSG
 *
 * Commands:
 *   SEED:DRBG:0:hexseed - Seed deterministic RNG
 *   KEYGEN:MLKEM:768:   - Generate ML-KEM keypair
 *   ENCAPS:MLKEM:768:pk - Encapsulate to public key
 *   DECAPS:MLKEM:768:ctsk - Decapsulate ciphertext with secret key
 *   KEYGEN:MLDSA:65:    - Generate ML-DSA keypair
 *   SIGN:MLDSA:65:skmsg - Sign message with secret key
 *   VERIFY:MLDSA:65:pkmsgsig - Verify signature
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/console/console.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>
#include <stdlib.h>

#define MAX_LINE_LEN 8192
#define MAX_HEX_LEN  (MAX_LINE_LEN / 2)

static uint8_t hex_buffer[MAX_HEX_LEN];
static uint8_t result_buffer[MAX_HEX_LEN];

/* Convert hex string to bytes */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return -1;
    }
    
    size_t byte_len = hex_len / 2;
    if (byte_len > MAX_HEX_LEN) {
        return -1;
    }
    
    for (size_t i = 0; i < byte_len; i++) {
        char byte_str[3] = { hex[i*2], hex[i*2+1], 0 };
        char *endptr;
        out[i] = (uint8_t)strtol(byte_str, &endptr, 16);
        if (*endptr != '\0') {
            return -1;
        }
    }
    
    *out_len = byte_len;
    return 0;
}

/* Convert bytes to hex string */
static void bytes_to_hex(const uint8_t *data, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i*2, "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

/* Process SEED command */
static void cmd_seed(const char *hex_seed)
{
    size_t seed_len;
    if (hex_to_bytes(hex_seed, hex_buffer, &seed_len) != 0) {
        printk("ERROR:INVALID_HEX\n");
        return;
    }
    
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
    int ret = pqcp_rng_deterministic_seed(hex_buffer, seed_len);
    if (ret == 0) {
        printk("RESULT:OK\n");
    } else {
        printk("ERROR:SEED_FAILED:%d\n", ret);
    }
#else
    printk("ERROR:DETERMINISTIC_NOT_ENABLED\n");
#endif
}

/* Process ML-KEM KEYGEN */
static void cmd_mlkem_keygen(int level)
{
    pqcp_mlkem_level_t mlkem_level;
    switch (level) {
    case 512:  mlkem_level = PQCP_MLKEM_512; break;
    case 768:  mlkem_level = PQCP_MLKEM_768; break;
    case 1024: mlkem_level = PQCP_MLKEM_1024; break;
    default:
        printk("ERROR:INVALID_LEVEL\n");
        return;
    }
    
    static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    
    int ret = pqcp_mlkem_keypair(mlkem_level, pk, sk);
    if (ret != PQCP_MLKEM_SUCCESS) {
        printk("ERROR:KEYGEN_FAILED:%d\n", ret);
        return;
    }
    
    size_t pk_size = pqcp_mlkem_pk_size(mlkem_level);
    size_t sk_size = pqcp_mlkem_sk_size(mlkem_level);
    
    /* Output: pk||sk in hex */
    static char hex_out[PQCP_MLKEM_PK_SIZE_MAX * 2 + PQCP_MLKEM_SK_SIZE_MAX * 2 + 1];
    bytes_to_hex(pk, pk_size, hex_out);
    bytes_to_hex(sk, sk_size, hex_out + pk_size * 2);
    
    printk("RESULT:%s\n", hex_out);
}

/* Process ML-KEM ENCAPS */
static void cmd_mlkem_encaps(int level, const char *hex_pk)
{
    pqcp_mlkem_level_t mlkem_level;
    switch (level) {
    case 512:  mlkem_level = PQCP_MLKEM_512; break;
    case 768:  mlkem_level = PQCP_MLKEM_768; break;
    case 1024: mlkem_level = PQCP_MLKEM_1024; break;
    default:
        printk("ERROR:INVALID_LEVEL\n");
        return;
    }
    
    size_t pk_len;
    if (hex_to_bytes(hex_pk, hex_buffer, &pk_len) != 0) {
        printk("ERROR:INVALID_HEX\n");
        return;
    }
    
    if (pk_len != pqcp_mlkem_pk_size(mlkem_level)) {
        printk("ERROR:WRONG_PK_SIZE\n");
        return;
    }
    
    static uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
    static uint8_t ss[PQCP_MLKEM_SS_SIZE];
    
    int ret = pqcp_mlkem_encapsulate(mlkem_level, hex_buffer, ct, ss);
    if (ret != PQCP_MLKEM_SUCCESS) {
        printk("ERROR:ENCAPS_FAILED:%d\n", ret);
        return;
    }
    
    size_t ct_size = pqcp_mlkem_ct_size(mlkem_level);
    
    /* Output: ct||ss in hex */
    static char hex_out[PQCP_MLKEM_CT_SIZE_MAX * 2 + PQCP_MLKEM_SS_SIZE * 2 + 1];
    bytes_to_hex(ct, ct_size, hex_out);
    bytes_to_hex(ss, PQCP_MLKEM_SS_SIZE, hex_out + ct_size * 2);
    
    printk("RESULT:%s\n", hex_out);
}

/* Process ML-KEM DECAPS */
static void cmd_mlkem_decaps(int level, const char *hex_ct_sk)
{
    pqcp_mlkem_level_t mlkem_level;
    switch (level) {
    case 512:  mlkem_level = PQCP_MLKEM_512; break;
    case 768:  mlkem_level = PQCP_MLKEM_768; break;
    case 1024: mlkem_level = PQCP_MLKEM_1024; break;
    default:
        printk("ERROR:INVALID_LEVEL\n");
        return;
    }
    
    size_t data_len;
    if (hex_to_bytes(hex_ct_sk, hex_buffer, &data_len) != 0) {
        printk("ERROR:INVALID_HEX\n");
        return;
    }
    
    size_t ct_size = pqcp_mlkem_ct_size(mlkem_level);
    size_t sk_size = pqcp_mlkem_sk_size(mlkem_level);
    
    if (data_len != ct_size + sk_size) {
        printk("ERROR:WRONG_DATA_SIZE\n");
        return;
    }
    
    const uint8_t *ct = hex_buffer;
    const uint8_t *sk = hex_buffer + ct_size;
    static uint8_t ss[PQCP_MLKEM_SS_SIZE];
    
    int ret = pqcp_mlkem_decapsulate(mlkem_level, ct, sk, ss);
    if (ret != PQCP_MLKEM_SUCCESS) {
        printk("ERROR:DECAPS_FAILED:%d\n", ret);
        return;
    }
    
    static char hex_out[PQCP_MLKEM_SS_SIZE * 2 + 1];
    bytes_to_hex(ss, PQCP_MLKEM_SS_SIZE, hex_out);
    
    printk("RESULT:%s\n", hex_out);
}

/* Process ML-DSA KEYGEN */
static void cmd_mldsa_keygen(int level)
{
    pqcp_mldsa_level_t mldsa_level;
    switch (level) {
    case 44: mldsa_level = PQCP_MLDSA_44; break;
    case 65: mldsa_level = PQCP_MLDSA_65; break;
    case 87: mldsa_level = PQCP_MLDSA_87; break;
    default:
        printk("ERROR:INVALID_LEVEL\n");
        return;
    }
    
    static uint8_t pk[PQCP_MLDSA_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLDSA_SK_SIZE_MAX];
    
    int ret = pqcp_mldsa_keypair(mldsa_level, pk, sk);
    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("ERROR:KEYGEN_FAILED:%d\n", ret);
        return;
    }
    
    size_t pk_size = pqcp_mldsa_pk_size(mldsa_level);
    size_t sk_size = pqcp_mldsa_sk_size(mldsa_level);
    
    static char hex_out[PQCP_MLDSA_PK_SIZE_MAX * 2 + PQCP_MLDSA_SK_SIZE_MAX * 2 + 1];
    bytes_to_hex(pk, pk_size, hex_out);
    bytes_to_hex(sk, sk_size, hex_out + pk_size * 2);
    
    printk("RESULT:%s\n", hex_out);
}

/* Process ML-DSA SIGN */
static void cmd_mldsa_sign(int level, const char *hex_sk_msg)
{
    pqcp_mldsa_level_t mldsa_level;
    switch (level) {
    case 44: mldsa_level = PQCP_MLDSA_44; break;
    case 65: mldsa_level = PQCP_MLDSA_65; break;
    case 87: mldsa_level = PQCP_MLDSA_87; break;
    default:
        printk("ERROR:INVALID_LEVEL\n");
        return;
    }
    
    size_t data_len;
    if (hex_to_bytes(hex_sk_msg, hex_buffer, &data_len) != 0) {
        printk("ERROR:INVALID_HEX\n");
        return;
    }
    
    size_t sk_size = pqcp_mldsa_sk_size(mldsa_level);
    
    if (data_len <= sk_size) {
        printk("ERROR:MISSING_MESSAGE\n");
        return;
    }
    
    const uint8_t *sk = hex_buffer;
    const uint8_t *msg = hex_buffer + sk_size;
    size_t msg_len = data_len - sk_size;
    
    static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
    
    int ret = pqcp_mldsa_sign(mldsa_level, sk, msg, msg_len, NULL, 0, sig);
    if (ret != PQCP_MLDSA_SUCCESS) {
        printk("ERROR:SIGN_FAILED:%d\n", ret);
        return;
    }
    
    size_t sig_size = pqcp_mldsa_sig_size(mldsa_level);
    
    static char hex_out[PQCP_MLDSA_SIG_SIZE_MAX * 2 + 1];
    bytes_to_hex(sig, sig_size, hex_out);
    
    printk("RESULT:%s\n", hex_out);
}

/* Process ML-DSA VERIFY */
static void cmd_mldsa_verify(int level, const char *hex_pk_msg_sig)
{
    pqcp_mldsa_level_t mldsa_level;
    switch (level) {
    case 44: mldsa_level = PQCP_MLDSA_44; break;
    case 65: mldsa_level = PQCP_MLDSA_65; break;
    case 87: mldsa_level = PQCP_MLDSA_87; break;
    default:
        printk("ERROR:INVALID_LEVEL\n");
        return;
    }
    
    size_t data_len;
    if (hex_to_bytes(hex_pk_msg_sig, hex_buffer, &data_len) != 0) {
        printk("ERROR:INVALID_HEX\n");
        return;
    }
    
    size_t pk_size = pqcp_mldsa_pk_size(mldsa_level);
    size_t sig_size = pqcp_mldsa_sig_size(mldsa_level);
    
    if (data_len < pk_size + sig_size + 1) {
        printk("ERROR:MISSING_DATA\n");
        return;
    }
    
    const uint8_t *pk = hex_buffer;
    size_t msg_len = data_len - pk_size - sig_size;
    const uint8_t *msg = hex_buffer + pk_size;
    const uint8_t *sig = hex_buffer + pk_size + msg_len;
    
    int ret = pqcp_mldsa_verify(mldsa_level, pk, msg, msg_len, NULL, 0, sig);
    
    if (ret == PQCP_MLDSA_SUCCESS) {
        printk("RESULT:VALID\n");
    } else if (ret == PQCP_MLDSA_ERR_VERIFY) {
        printk("RESULT:INVALID\n");
    } else {
        printk("ERROR:VERIFY_FAILED:%d\n", ret);
    }
}

/* Parse and execute command line */
static void process_command(char *line)
{
    /* Format: CMD:ALG:LEVEL:DATA */
    char *cmd = strtok(line, ":");
    char *alg = strtok(NULL, ":");
    char *level_str = strtok(NULL, ":");
    char *data = strtok(NULL, ":");
    
    if (cmd == NULL) {
        printk("ERROR:EMPTY_CMD\n");
        return;
    }
    
    /* HELP command */
    if (strcmp(cmd, "HELP") == 0) {
        printk("Commands:\n");
        printk("  SEED:DRBG:0:<hexseed>     - Seed deterministic RNG\n");
        printk("  KEYGEN:MLKEM:<512|768|1024>: - Generate ML-KEM keypair\n");
        printk("  ENCAPS:MLKEM:<level>:<pk>    - Encapsulate with public key\n");
        printk("  DECAPS:MLKEM:<level>:<ct||sk> - Decapsulate ciphertext\n");
        printk("  KEYGEN:MLDSA:<44|65|87>:  - Generate ML-DSA keypair\n");
        printk("  SIGN:MLDSA:<level>:<sk||msg> - Sign message\n");
        printk("  VERIFY:MLDSA:<level>:<pk||msg||sig> - Verify signature\n");
        printk("  SELFTEST::                - Run internal self-test\n");
        printk("RESULT:OK\n");
        return;
    }
    
    /* SELFTEST command */
    if (strcmp(cmd, "SELFTEST") == 0) {
        printk("Running self-test...\n");
        
        /* Seed deterministic RNG for selftest */
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
        static const uint8_t selftest_seed[48] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30
        };
        pqcp_rng_deterministic_seed(selftest_seed, sizeof(selftest_seed));
#endif
        
        /* Quick ML-KEM test */
        static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
        static uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
        static uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
        static uint8_t ss1[PQCP_MLKEM_SS_SIZE], ss2[PQCP_MLKEM_SS_SIZE];
        
        pqcp_mlkem_level_t kem_level = PQCP_MLKEM_768;
        int ret = pqcp_mlkem_keypair(kem_level, pk, sk);
        if (ret != PQCP_MLKEM_SUCCESS) {
            printk("ERROR:MLKEM_KEYGEN:%d\n", ret);
            return;
        }
        
        ret = pqcp_mlkem_encapsulate(kem_level, pk, ct, ss1);
        if (ret != PQCP_MLKEM_SUCCESS) {
            printk("ERROR:MLKEM_ENCAPS:%d\n", ret);
            return;
        }
        
        ret = pqcp_mlkem_decapsulate(kem_level, ct, sk, ss2);
        if (ret != PQCP_MLKEM_SUCCESS || memcmp(ss1, ss2, PQCP_MLKEM_SS_SIZE) != 0) {
            printk("ERROR:MLKEM_DECAPS:%d\n", ret);
            return;
        }
        
        printk("  ML-KEM-768: PASS\n");
        
        /* Re-seed for ML-DSA */
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
        pqcp_rng_deterministic_seed(selftest_seed, sizeof(selftest_seed));
#endif
        
        /* Quick ML-DSA test */
        static uint8_t dsa_pk[PQCP_MLDSA_PK_SIZE_MAX];
        static uint8_t dsa_sk[PQCP_MLDSA_SK_SIZE_MAX];
        static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
        const uint8_t msg[] = "selftest";
        
        pqcp_mldsa_level_t dsa_level = PQCP_MLDSA_65;
        ret = pqcp_mldsa_keypair(dsa_level, dsa_pk, dsa_sk);
        if (ret != PQCP_MLDSA_SUCCESS) {
            printk("ERROR:MLDSA_KEYGEN:%d\n", ret);
            return;
        }
        
        /* Re-seed again for sign (it needs randomness) */
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
        pqcp_rng_deterministic_seed(selftest_seed, sizeof(selftest_seed));
#endif
        
        ret = pqcp_mldsa_sign(dsa_level, dsa_sk, msg, sizeof(msg)-1, NULL, 0, sig);
        if (ret != PQCP_MLDSA_SUCCESS) {
            printk("ERROR:MLDSA_SIGN:%d\n", ret);
            return;
        }
        
        ret = pqcp_mldsa_verify(dsa_level, dsa_pk, msg, sizeof(msg)-1, NULL, 0, sig);
        if (ret != PQCP_MLDSA_SUCCESS) {
            printk("ERROR:MLDSA_VERIFY:%d\n", ret);
            return;
        }
        
        printk("  ML-DSA-65: PASS\n");
        printk("RESULT:SELFTEST_OK\n");
        return;
    }
    
    /* SEED command */
    if (strcmp(cmd, "SEED") == 0) {
        if (data == NULL) data = "";
        cmd_seed(data);
        return;
    }
    
    if (alg == NULL || level_str == NULL) {
        printk("ERROR:MISSING_ARGS\n");
        return;
    }
    
    int level = atoi(level_str);
    if (data == NULL) data = "";
    
    /* KEYGEN commands */
    if (strcmp(cmd, "KEYGEN") == 0) {
        if (strcmp(alg, "MLKEM") == 0) {
            cmd_mlkem_keygen(level);
        } else if (strcmp(alg, "MLDSA") == 0) {
            cmd_mldsa_keygen(level);
        } else {
            printk("ERROR:UNKNOWN_ALG\n");
        }
        return;
    }
    
    /* ENCAPS command */
    if (strcmp(cmd, "ENCAPS") == 0 && strcmp(alg, "MLKEM") == 0) {
        cmd_mlkem_encaps(level, data);
        return;
    }
    
    /* DECAPS command */
    if (strcmp(cmd, "DECAPS") == 0 && strcmp(alg, "MLKEM") == 0) {
        cmd_mlkem_decaps(level, data);
        return;
    }
    
    /* SIGN command */
    if (strcmp(cmd, "SIGN") == 0 && strcmp(alg, "MLDSA") == 0) {
        cmd_mldsa_sign(level, data);
        return;
    }
    
    /* VERIFY command */
    if (strcmp(cmd, "VERIFY") == 0 && strcmp(alg, "MLDSA") == 0) {
        cmd_mldsa_verify(level, data);
        return;
    }
    
    printk("ERROR:UNKNOWN_CMD\n");
}

int main(void)
{
    printk("\n");
    printk("PQCP Serial ACVP Interface\n");
    printk("==========================\n");
    printk("Ready for commands. Format: CMD:ALG:LEVEL:HEX_DATA\n");
    printk("Commands: SEED, KEYGEN, ENCAPS, DECAPS, SIGN, VERIFY\n");
    printk("\n");
    
    /* Initialize RNG (deterministic mode) */
    pqcp_rng_init();
    
    console_init();
    
    static char line_buffer[MAX_LINE_LEN];
    
    while (1) {
        printk("> ");
        
        /* Read line from console */
        int len = 0;
        char c;
        
        while (len < MAX_LINE_LEN - 1) {
            c = console_getchar();
            
            if (c == '\r' || c == '\n') {
                break;
            }
            
            if (c == '\b' && len > 0) {
                len--;
                continue;
            }
            
            line_buffer[len++] = c;
        }
        
        line_buffer[len] = '\0';
        
        if (len > 0) {
            process_command(line_buffer);
        }
    }
    
    return 0;
}
