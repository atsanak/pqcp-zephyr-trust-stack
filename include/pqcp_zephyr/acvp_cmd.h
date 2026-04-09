/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP ACVP Command Library
 *
 * Reusable command handlers for ACVP testing. These can be used
 * by the serial ACVP sample or programmatically by tests.
 */

#ifndef PQCP_ZEPHYR_ACVP_CMD_H_
#define PQCP_ZEPHYR_ACVP_CMD_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup pqcp_acvp_cmd PQCP ACVP Command Library
 * @{
 */

/**
 * @brief ACVP command result codes
 */
enum pqcp_acvp_result {
    PQCP_ACVP_OK = 0,              /**< Success */
    PQCP_ACVP_ERR_INVALID_HEX,     /**< Invalid hex input */
    PQCP_ACVP_ERR_INVALID_LEVEL,   /**< Invalid algorithm level */
    PQCP_ACVP_ERR_INVALID_ALG,     /**< Unknown algorithm */
    PQCP_ACVP_ERR_INVALID_CMD,     /**< Unknown command */
    PQCP_ACVP_ERR_MISSING_ARGS,    /**< Missing arguments */
    PQCP_ACVP_ERR_WRONG_SIZE,      /**< Wrong input data size */
    PQCP_ACVP_ERR_KEYGEN,          /**< Key generation failed */
    PQCP_ACVP_ERR_ENCAPS,          /**< Encapsulation failed */
    PQCP_ACVP_ERR_DECAPS,          /**< Decapsulation failed */
    PQCP_ACVP_ERR_SIGN,            /**< Signing failed */
    PQCP_ACVP_ERR_VERIFY,          /**< Verification failed (not invalid signature) */
    PQCP_ACVP_ERR_SEED,            /**< RNG seeding failed */
    PQCP_ACVP_ERR_NOT_ENABLED,     /**< Feature not enabled in build */
    PQCP_ACVP_ERR_BUFFER_TOO_SMALL,/**< Output buffer too small */
    PQCP_ACVP_VERIFY_INVALID,      /**< Signature is invalid (not an error) */
};

/**
 * @brief ACVP response structure
 * 
 * Holds the result of an ACVP command execution.
 */
struct pqcp_acvp_response {
    enum pqcp_acvp_result result;  /**< Result code */
    uint8_t *data;                 /**< Output data buffer (caller-provided) */
    size_t data_len;               /**< Length of output data */
    size_t data_cap;               /**< Capacity of output buffer */
};

/**
 * @brief Convert error code to string description
 */
const char *pqcp_acvp_result_str(enum pqcp_acvp_result result);

/**
 * @brief Format a command response into the serial ACVP wire format.
 *
 * The formatter preserves the stable host-visible response grammar used by
 * the serial sample:
 *
 * - `RESULT:OK`
 * - `RESULT:INVALID`
 * - `RESULT:<hex payload>`
 * - `ERROR:<error_code>`
 *
 * @param resp Parsed command response.
 * @param out Destination buffer for the formatted line.
 * @param out_size Capacity of @p out in bytes.
 *
 * @retval 0 Response formatted successfully.
 * @retval -EINVAL Invalid arguments were provided.
 * @retval -ENOSPC @p out is too small for the formatted line.
 */
int pqcp_acvp_format_response_line(const struct pqcp_acvp_response *resp,
                                   char *out, size_t out_size);

/**
 * @brief Initialize an ACVP response structure
 * 
 * @param resp Response structure to initialize
 * @param buffer Output buffer to use
 * @param buffer_size Size of output buffer
 */
void pqcp_acvp_response_init(struct pqcp_acvp_response *resp,
                             uint8_t *buffer, size_t buffer_size);

/**
 * @brief Seed the deterministic RNG
 * 
 * @param seed Seed bytes
 * @param seed_len Length of seed
 * @param resp Response structure
 * @return 0 on success, negative errno on failure
 */
int pqcp_acvp_cmd_seed(const uint8_t *seed, size_t seed_len,
                       struct pqcp_acvp_response *resp);

/**
 * @brief Generate ML-KEM keypair
 * 
 * @param level ML-KEM level (512, 768, or 1024)
 * @param resp Response structure (data = pk||sk)
 * @return 0 on success, negative errno on failure
 */
int pqcp_acvp_cmd_mlkem_keygen(int level, struct pqcp_acvp_response *resp);

/**
 * @brief Encapsulate with ML-KEM
 * 
 * @param level ML-KEM level
 * @param pk Public key
 * @param pk_len Public key length
 * @param resp Response structure (data = ct||ss)
 * @return 0 on success, negative errno on failure
 */
int pqcp_acvp_cmd_mlkem_encaps(int level, const uint8_t *pk, size_t pk_len,
                               struct pqcp_acvp_response *resp);

/**
 * @brief Decapsulate with ML-KEM
 * 
 * @param level ML-KEM level
 * @param ct Ciphertext
 * @param ct_len Ciphertext length
 * @param sk Secret key
 * @param sk_len Secret key length
 * @param resp Response structure (data = ss)
 * @return 0 on success, negative errno on failure
 */
int pqcp_acvp_cmd_mlkem_decaps(int level,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t *sk, size_t sk_len,
                               struct pqcp_acvp_response *resp);

/**
 * @brief Generate ML-DSA keypair
 * 
 * @param level ML-DSA level (44, 65, or 87)
 * @param resp Response structure (data = pk||sk)
 * @return 0 on success, negative errno on failure
 */
int pqcp_acvp_cmd_mldsa_keygen(int level, struct pqcp_acvp_response *resp);

/**
 * @brief Sign with ML-DSA
 * 
 * @param level ML-DSA level
 * @param sk Secret key
 * @param sk_len Secret key length
 * @param msg Message to sign
 * @param msg_len Message length
 * @param resp Response structure (data = sig)
 * @return 0 on success, negative errno on failure
 */
int pqcp_acvp_cmd_mldsa_sign(int level,
                             const uint8_t *sk, size_t sk_len,
                             const uint8_t *msg, size_t msg_len,
                             struct pqcp_acvp_response *resp);

/**
 * @brief Verify with ML-DSA
 * 
 * @param level ML-DSA level
 * @param pk Public key
 * @param pk_len Public key length
 * @param msg Message
 * @param msg_len Message length
 * @param sig Signature
 * @param sig_len Signature length
 * @param resp Response structure (result = OK if valid, VERIFY_INVALID if invalid)
 * @return 0 on success (check resp->result for validity), negative errno on failure
 */
int pqcp_acvp_cmd_mldsa_verify(int level,
                               const uint8_t *pk, size_t pk_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len,
                               struct pqcp_acvp_response *resp);

/**
 * @brief Run self-test
 * 
 * Runs basic correctness tests for ML-KEM and ML-DSA.
 * 
 * @param resp Response structure
 * @return 0 on success, negative errno on failure
 */
int pqcp_acvp_cmd_selftest(struct pqcp_acvp_response *resp);

/**
 * @brief Hex encoding/decoding utilities
 */

/**
 * @brief Convert hex string to bytes
 * 
 * @param hex Null-terminated hex string
 * @param out Output buffer
 * @param out_len Pointer to receive output length
 * @param max_len Maximum output length
 * @return 0 on success, -EINVAL on invalid hex, -ENOSPC if buffer too small
 */
int pqcp_acvp_hex_to_bytes(const char *hex, uint8_t *out,
                           size_t *out_len, size_t max_len);

/**
 * @brief Convert bytes to hex string
 * 
 * @param data Input data
 * @param len Data length
 * @param out Output buffer (must be at least len*2 + 1 bytes)
 */
void pqcp_acvp_bytes_to_hex(const uint8_t *data, size_t len, char *out);

/**
 * @brief Parse and execute a command line
 * 
 * Parses a line in the format CMD:ALG:LEVEL:HEX_DATA and executes
 * the corresponding command.
 *
 * Supported commands are:
 *
 * - `SEED:DRBG:0:<hexseed>`
 * - `KEYGEN:MLKEM:<512|768|1024>:`
 * - `ENCAPS:MLKEM:<level>:<pk_hex>`
 * - `DECAPS:MLKEM:<level>:<ct_hex><sk_hex>`
 * - `KEYGEN:MLDSA:<44|65|87>:`
 * - `SIGN:MLDSA:<level>:<sk_hex><msg_hex>`
 * - `VERIFY:MLDSA:<level>:<pk_hex><msg_hex><sig_hex>`
 * - `SELFTEST::`
 * - `HELP::`
 * 
 * @param line Command line (will be modified by strtok)
 * @param work_buf Working buffer for hex decoding
 * @param work_buf_size Size of working buffer
 * @param resp Response structure
 * @return 0 on success, negative errno on failure
 */
int pqcp_acvp_process_command(char *line,
                              uint8_t *work_buf, size_t work_buf_size,
                              struct pqcp_acvp_response *resp);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_ACVP_CMD_H_ */
