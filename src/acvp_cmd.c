/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP ACVP Command Library Implementation
 */

#include <pqcp_zephyr/acvp_cmd.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>

const char *pqcp_acvp_result_str(enum pqcp_acvp_result result)
{
    switch (result) {
    case PQCP_ACVP_OK:               return "OK";
    case PQCP_ACVP_ERR_INVALID_HEX:  return "INVALID_HEX";
    case PQCP_ACVP_ERR_INVALID_LEVEL: return "INVALID_LEVEL";
    case PQCP_ACVP_ERR_INVALID_ALG:  return "INVALID_ALG";
    case PQCP_ACVP_ERR_INVALID_CMD:  return "INVALID_CMD";
    case PQCP_ACVP_ERR_MISSING_ARGS: return "MISSING_ARGS";
    case PQCP_ACVP_ERR_WRONG_SIZE:   return "WRONG_SIZE";
    case PQCP_ACVP_ERR_KEYGEN:       return "KEYGEN_FAILED";
    case PQCP_ACVP_ERR_ENCAPS:       return "ENCAPS_FAILED";
    case PQCP_ACVP_ERR_DECAPS:       return "DECAPS_FAILED";
    case PQCP_ACVP_ERR_SIGN:         return "SIGN_FAILED";
    case PQCP_ACVP_ERR_VERIFY:       return "VERIFY_FAILED";
    case PQCP_ACVP_ERR_SEED:         return "SEED_FAILED";
    case PQCP_ACVP_ERR_NOT_ENABLED:  return "NOT_ENABLED";
    case PQCP_ACVP_ERR_BUFFER_TOO_SMALL: return "BUFFER_TOO_SMALL";
    case PQCP_ACVP_VERIFY_INVALID:   return "INVALID";
    default: return "UNKNOWN";
    }
}

void pqcp_acvp_response_init(struct pqcp_acvp_response *resp,
                             uint8_t *buffer, size_t buffer_size)
{
    resp->result = PQCP_ACVP_OK;
    resp->data = buffer;
    resp->data_len = 0;
    resp->data_cap = buffer_size;
}

int pqcp_acvp_hex_to_bytes(const char *hex, uint8_t *out,
                           size_t *out_len, size_t max_len)
{
    if (hex == NULL) {
        *out_len = 0;
        return 0;
    }

    size_t hex_len = strlen(hex);
    
    /* Must be even length */
    if (hex_len % 2 != 0) {
        return -EINVAL;
    }
    
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) {
        return -ENOSPC;
    }
    
    for (size_t i = 0; i < byte_len; i++) {
        char byte_str[3] = { hex[i*2], hex[i*2+1], 0 };
        char *endptr;
        unsigned long val = strtoul(byte_str, &endptr, 16);
        if (*endptr != '\0') {
            return -EINVAL;
        }
        out[i] = (uint8_t)val;
    }
    
    *out_len = byte_len;
    return 0;
}

void pqcp_acvp_bytes_to_hex(const uint8_t *data, size_t len, char *out)
{
    static const char hex_chars[] = "0123456789abcdef";
    
    for (size_t i = 0; i < len; i++) {
        out[i*2] = hex_chars[(data[i] >> 4) & 0xF];
        out[i*2+1] = hex_chars[data[i] & 0xF];
    }
    out[len * 2] = '\0';
}

/* Helper to convert level int to enum */
static pqcp_mlkem_level_t get_mlkem_level(int level)
{
    switch (level) {
    case 512:  return PQCP_MLKEM_512;
    case 768:  return PQCP_MLKEM_768;
    case 1024: return PQCP_MLKEM_1024;
    default:   return (pqcp_mlkem_level_t)-1;
    }
}

static pqcp_mldsa_level_t get_mldsa_level(int level)
{
    switch (level) {
    case 44: return PQCP_MLDSA_44;
    case 65: return PQCP_MLDSA_65;
    case 87: return PQCP_MLDSA_87;
    default: return (pqcp_mldsa_level_t)-1;
    }
}

int pqcp_acvp_cmd_seed(const uint8_t *seed, size_t seed_len,
                       struct pqcp_acvp_response *resp)
{
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
    int ret = pqcp_rng_deterministic_seed(seed, seed_len);
    if (ret == 0) {
        resp->result = PQCP_ACVP_OK;
        resp->data_len = 0;
        return 0;
    } else {
        resp->result = PQCP_ACVP_ERR_SEED;
        return -EIO;
    }
#else
    (void)seed;
    (void)seed_len;
    resp->result = PQCP_ACVP_ERR_NOT_ENABLED;
    return -ENOTSUP;
#endif
}

int pqcp_acvp_cmd_mlkem_keygen(int level, struct pqcp_acvp_response *resp)
{
    pqcp_mlkem_level_t mlkem_level = get_mlkem_level(level);
    if ((int)mlkem_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }
    
    size_t pk_size = pqcp_mlkem_pk_size(mlkem_level);
    size_t sk_size = pqcp_mlkem_sk_size(mlkem_level);
    
    if (pk_size + sk_size > resp->data_cap) {
        resp->result = PQCP_ACVP_ERR_BUFFER_TOO_SMALL;
        return -ENOSPC;
    }
    
    uint8_t *pk = resp->data;
    uint8_t *sk = resp->data + pk_size;
    
    int ret = pqcp_mlkem_keypair(mlkem_level, pk, sk);
    if (ret != PQCP_MLKEM_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_KEYGEN;
        return -EIO;
    }
    
    resp->result = PQCP_ACVP_OK;
    resp->data_len = pk_size + sk_size;
    return 0;
}

int pqcp_acvp_cmd_mlkem_encaps(int level, const uint8_t *pk, size_t pk_len,
                               struct pqcp_acvp_response *resp)
{
    pqcp_mlkem_level_t mlkem_level = get_mlkem_level(level);
    if ((int)mlkem_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }
    
    if (pk_len != pqcp_mlkem_pk_size(mlkem_level)) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }
    
    size_t ct_size = pqcp_mlkem_ct_size(mlkem_level);
    
    if (ct_size + PQCP_MLKEM_SS_SIZE > resp->data_cap) {
        resp->result = PQCP_ACVP_ERR_BUFFER_TOO_SMALL;
        return -ENOSPC;
    }
    
    uint8_t *ct = resp->data;
    uint8_t *ss = resp->data + ct_size;
    
    int ret = pqcp_mlkem_encapsulate(mlkem_level, pk, ct, ss);
    if (ret != PQCP_MLKEM_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_ENCAPS;
        return -EIO;
    }
    
    resp->result = PQCP_ACVP_OK;
    resp->data_len = ct_size + PQCP_MLKEM_SS_SIZE;
    return 0;
}

int pqcp_acvp_cmd_mlkem_decaps(int level,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t *sk, size_t sk_len,
                               struct pqcp_acvp_response *resp)
{
    pqcp_mlkem_level_t mlkem_level = get_mlkem_level(level);
    if ((int)mlkem_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }
    
    if (ct_len != pqcp_mlkem_ct_size(mlkem_level)) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }
    
    if (sk_len != pqcp_mlkem_sk_size(mlkem_level)) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }
    
    if (PQCP_MLKEM_SS_SIZE > resp->data_cap) {
        resp->result = PQCP_ACVP_ERR_BUFFER_TOO_SMALL;
        return -ENOSPC;
    }
    
    int ret = pqcp_mlkem_decapsulate(mlkem_level, ct, sk, resp->data);
    if (ret != PQCP_MLKEM_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_DECAPS;
        return -EIO;
    }
    
    resp->result = PQCP_ACVP_OK;
    resp->data_len = PQCP_MLKEM_SS_SIZE;
    return 0;
}

int pqcp_acvp_cmd_mldsa_keygen(int level, struct pqcp_acvp_response *resp)
{
    pqcp_mldsa_level_t mldsa_level = get_mldsa_level(level);
    if ((int)mldsa_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }
    
    size_t pk_size = pqcp_mldsa_pk_size(mldsa_level);
    size_t sk_size = pqcp_mldsa_sk_size(mldsa_level);
    
    if (pk_size + sk_size > resp->data_cap) {
        resp->result = PQCP_ACVP_ERR_BUFFER_TOO_SMALL;
        return -ENOSPC;
    }
    
    uint8_t *pk = resp->data;
    uint8_t *sk = resp->data + pk_size;
    
    int ret = pqcp_mldsa_keypair(mldsa_level, pk, sk);
    if (ret != PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_KEYGEN;
        return -EIO;
    }
    
    resp->result = PQCP_ACVP_OK;
    resp->data_len = pk_size + sk_size;
    return 0;
}

int pqcp_acvp_cmd_mldsa_sign(int level,
                             const uint8_t *sk, size_t sk_len,
                             const uint8_t *msg, size_t msg_len,
                             struct pqcp_acvp_response *resp)
{
    pqcp_mldsa_level_t mldsa_level = get_mldsa_level(level);
    if ((int)mldsa_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }
    
    if (sk_len != pqcp_mldsa_sk_size(mldsa_level)) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }
    
    size_t sig_size = pqcp_mldsa_sig_size(mldsa_level);
    
    if (sig_size > resp->data_cap) {
        resp->result = PQCP_ACVP_ERR_BUFFER_TOO_SMALL;
        return -ENOSPC;
    }
    
    int ret = pqcp_mldsa_sign(mldsa_level, sk, msg, msg_len, NULL, 0, resp->data);
    if (ret != PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_SIGN;
        return -EIO;
    }
    
    resp->result = PQCP_ACVP_OK;
    resp->data_len = sig_size;
    return 0;
}

int pqcp_acvp_cmd_mldsa_verify(int level,
                               const uint8_t *pk, size_t pk_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len,
                               struct pqcp_acvp_response *resp)
{
    pqcp_mldsa_level_t mldsa_level = get_mldsa_level(level);
    if ((int)mldsa_level < 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }
    
    if (pk_len != pqcp_mldsa_pk_size(mldsa_level)) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }
    
    if (sig_len != pqcp_mldsa_sig_size(mldsa_level)) {
        resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
        return -EINVAL;
    }
    
    resp->data_len = 0;
    
    int ret = pqcp_mldsa_verify(mldsa_level, pk, msg, msg_len, NULL, 0, sig);
    
    if (ret == PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_OK;
        return 0;
    } else if (ret == PQCP_MLDSA_ERR_VERIFY) {
        resp->result = PQCP_ACVP_VERIFY_INVALID;
        return 0;  /* Not an error, just invalid signature */
    } else {
        resp->result = PQCP_ACVP_ERR_VERIFY;
        return -EIO;
    }
}

int pqcp_acvp_cmd_selftest(struct pqcp_acvp_response *resp)
{
    /* Use local buffers for selftest */
    static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    static uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
    static uint8_t ss1[PQCP_MLKEM_SS_SIZE], ss2[PQCP_MLKEM_SS_SIZE];
    
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
    /* Seed for reproducibility */
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
    
    /* ML-KEM test */
    pqcp_mlkem_level_t kem_level = PQCP_MLKEM_768;
    
    int ret = pqcp_mlkem_keypair(kem_level, pk, sk);
    if (ret != PQCP_MLKEM_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_KEYGEN;
        return -EIO;
    }
    
    ret = pqcp_mlkem_encapsulate(kem_level, pk, ct, ss1);
    if (ret != PQCP_MLKEM_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_ENCAPS;
        return -EIO;
    }
    
    ret = pqcp_mlkem_decapsulate(kem_level, ct, sk, ss2);
    if (ret != PQCP_MLKEM_SUCCESS || memcmp(ss1, ss2, PQCP_MLKEM_SS_SIZE) != 0) {
        resp->result = PQCP_ACVP_ERR_DECAPS;
        return -EIO;
    }
    
    /* ML-DSA test - use larger buffers */
    static uint8_t dsa_pk[PQCP_MLDSA_PK_SIZE_MAX];
    static uint8_t dsa_sk[PQCP_MLDSA_SK_SIZE_MAX];
    static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
    static const uint8_t msg[] = "selftest";
    
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
    pqcp_rng_deterministic_seed(selftest_seed, sizeof(selftest_seed));
#endif
    
    pqcp_mldsa_level_t dsa_level = PQCP_MLDSA_65;
    
    ret = pqcp_mldsa_keypair(dsa_level, dsa_pk, dsa_sk);
    if (ret != PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_KEYGEN;
        return -EIO;
    }
    
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
    pqcp_rng_deterministic_seed(selftest_seed, sizeof(selftest_seed));
#endif
    
    ret = pqcp_mldsa_sign(dsa_level, dsa_sk, msg, sizeof(msg)-1, NULL, 0, sig);
    if (ret != PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_SIGN;
        return -EIO;
    }
    
    ret = pqcp_mldsa_verify(dsa_level, dsa_pk, msg, sizeof(msg)-1, NULL, 0, sig);
    if (ret != PQCP_MLDSA_SUCCESS) {
        resp->result = PQCP_ACVP_ERR_VERIFY;
        return -EIO;
    }
    
    resp->result = PQCP_ACVP_OK;
    resp->data_len = 0;
    return 0;
}

int pqcp_acvp_process_command(char *line,
                              uint8_t *work_buf, size_t work_buf_size,
                              struct pqcp_acvp_response *resp)
{
    /* Format: CMD:ALG:LEVEL:DATA */
    char *cmd = strtok(line, ":");
    char *alg = strtok(NULL, ":");
    char *level_str = strtok(NULL, ":");
    char *data = strtok(NULL, ":");
    
    if (cmd == NULL || cmd[0] == '\0') {
        resp->result = PQCP_ACVP_ERR_INVALID_CMD;
        return -EINVAL;
    }
    
    /* HELP command */
    if (strcmp(cmd, "HELP") == 0) {
        resp->result = PQCP_ACVP_OK;
        resp->data_len = 0;
        return 0;
    }
    
    /* SELFTEST command */
    if (strcmp(cmd, "SELFTEST") == 0) {
        return pqcp_acvp_cmd_selftest(resp);
    }
    
    /* SEED command */
    if (strcmp(cmd, "SEED") == 0) {
        size_t seed_len;
        int ret = pqcp_acvp_hex_to_bytes(data, work_buf, &seed_len, work_buf_size);
        if (ret != 0) {
            resp->result = PQCP_ACVP_ERR_INVALID_HEX;
            return ret;
        }
        return pqcp_acvp_cmd_seed(work_buf, seed_len, resp);
    }
    
    /* Commands that require ALG and LEVEL */
    if (alg == NULL || level_str == NULL) {
        resp->result = PQCP_ACVP_ERR_MISSING_ARGS;
        return -EINVAL;
    }
    
    int level = atoi(level_str);
    if (level <= 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
        return -EINVAL;
    }
    
    /* KEYGEN command */
    if (strcmp(cmd, "KEYGEN") == 0) {
        if (strcmp(alg, "MLKEM") == 0) {
            return pqcp_acvp_cmd_mlkem_keygen(level, resp);
        } else if (strcmp(alg, "MLDSA") == 0) {
            return pqcp_acvp_cmd_mldsa_keygen(level, resp);
        } else {
            resp->result = PQCP_ACVP_ERR_INVALID_ALG;
            return -EINVAL;
        }
    }
    
    /* Commands that require DATA */
    size_t data_len = 0;
    int ret = pqcp_acvp_hex_to_bytes(data, work_buf, &data_len, work_buf_size);
    if (ret != 0) {
        resp->result = PQCP_ACVP_ERR_INVALID_HEX;
        return ret;
    }
    
    /* ML-KEM commands */
    if (strcmp(alg, "MLKEM") == 0) {
        if (strcmp(cmd, "ENCAPS") == 0) {
            return pqcp_acvp_cmd_mlkem_encaps(level, work_buf, data_len, resp);
        } else if (strcmp(cmd, "DECAPS") == 0) {
            pqcp_mlkem_level_t mlkem_level = get_mlkem_level(level);
            if ((int)mlkem_level < 0) {
                resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
                return -EINVAL;
            }
            size_t ct_size = pqcp_mlkem_ct_size(mlkem_level);
            if (data_len <= ct_size) {
                resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
                return -EINVAL;
            }
            return pqcp_acvp_cmd_mlkem_decaps(level,
                                              work_buf, ct_size,
                                              work_buf + ct_size, data_len - ct_size,
                                              resp);
        }
    }
    
    /* ML-DSA commands */
    if (strcmp(alg, "MLDSA") == 0) {
        if (strcmp(cmd, "SIGN") == 0) {
            pqcp_mldsa_level_t mldsa_level = get_mldsa_level(level);
            if ((int)mldsa_level < 0) {
                resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
                return -EINVAL;
            }
            size_t sk_size = pqcp_mldsa_sk_size(mldsa_level);
            if (data_len <= sk_size) {
                resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
                return -EINVAL;
            }
            return pqcp_acvp_cmd_mldsa_sign(level,
                                            work_buf, sk_size,
                                            work_buf + sk_size, data_len - sk_size,
                                            resp);
        } else if (strcmp(cmd, "VERIFY") == 0) {
            pqcp_mldsa_level_t mldsa_level = get_mldsa_level(level);
            if ((int)mldsa_level < 0) {
                resp->result = PQCP_ACVP_ERR_INVALID_LEVEL;
                return -EINVAL;
            }
            size_t pk_size = pqcp_mldsa_pk_size(mldsa_level);
            size_t sig_size = pqcp_mldsa_sig_size(mldsa_level);
            if (data_len < pk_size + sig_size + 1) {
                resp->result = PQCP_ACVP_ERR_WRONG_SIZE;
                return -EINVAL;
            }
            size_t msg_len = data_len - pk_size - sig_size;
            return pqcp_acvp_cmd_mldsa_verify(level,
                                              work_buf, pk_size,
                                              work_buf + pk_size, msg_len,
                                              work_buf + pk_size + msg_len, sig_size,
                                              resp);
        }
    }
    
    resp->result = PQCP_ACVP_ERR_INVALID_CMD;
    return -EINVAL;
}
