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
