/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Zephyr Trust Stack - ML-KEM API
 *
 * This header provides the Zephyr-facing API for ML-KEM (FIPS-203)
 * operations using mlkem-native as the underlying implementation.
 */

#ifndef PQCP_ZEPHYR_MLKEM_H
#define PQCP_ZEPHYR_MLKEM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ML-KEM Security Levels (FIPS-203)
 * 
 * ML-KEM-512:  NIST Level 1 (equivalent to AES-128)
 * ML-KEM-768:  NIST Level 3 (equivalent to AES-192) - Recommended default
 * ML-KEM-1024: NIST Level 5 (equivalent to AES-256)
 */

/**
 * @brief ML-KEM security parameter set selector.
 *
 * Values match the FIPS 203 parameter-set suffixes. Pass one of these values
 * to the ML-KEM size helpers and key generation, encapsulation, or
 * decapsulation entry points.
 */
typedef enum {
    PQCP_MLKEM_512  = 512,   /**< ML-KEM-512, NIST security level 1. */
    PQCP_MLKEM_768  = 768,   /**< ML-KEM-768, NIST security level 3. */
    PQCP_MLKEM_1024 = 1024   /**< ML-KEM-1024, NIST security level 5. */
} pqcp_mlkem_level_t;

/* Key and ciphertext sizes per security level */
#define PQCP_MLKEM_512_PK_SIZE      800
#define PQCP_MLKEM_512_SK_SIZE      1632
#define PQCP_MLKEM_512_CT_SIZE      768
#define PQCP_MLKEM_512_SS_SIZE      32

#define PQCP_MLKEM_768_PK_SIZE      1184
#define PQCP_MLKEM_768_SK_SIZE      2400
#define PQCP_MLKEM_768_CT_SIZE      1088
#define PQCP_MLKEM_768_SS_SIZE      32

#define PQCP_MLKEM_1024_PK_SIZE     1568
#define PQCP_MLKEM_1024_SK_SIZE     3168
#define PQCP_MLKEM_1024_CT_SIZE     1568
#define PQCP_MLKEM_1024_SS_SIZE     32

/* Maximum sizes (for static allocation at compile time) */
#define PQCP_MLKEM_PK_SIZE_MAX      PQCP_MLKEM_1024_PK_SIZE
#define PQCP_MLKEM_SK_SIZE_MAX      PQCP_MLKEM_1024_SK_SIZE
#define PQCP_MLKEM_CT_SIZE_MAX      PQCP_MLKEM_1024_CT_SIZE
#define PQCP_MLKEM_SS_SIZE          32  /* Same for all levels */

/* Error codes */
#define PQCP_MLKEM_SUCCESS          0
#define PQCP_MLKEM_ERR_INVALID_ARG  -1
#define PQCP_MLKEM_ERR_RNG          -2
#define PQCP_MLKEM_ERR_VERIFY       -3
#define PQCP_MLKEM_ERR_UNSUPPORTED  -4
#define PQCP_MLKEM_ERR_INTERNAL     -5

/**
 * @brief Get the public key size for a given security level.
 *
 * @param level The ML-KEM security level.
 * @return Size of the public key in bytes, or 0 if invalid.
 */
size_t pqcp_mlkem_pk_size(pqcp_mlkem_level_t level);

/**
 * @brief Get the secret key size for a given security level.
 *
 * @param level The ML-KEM security level.
 * @return Size of the secret key in bytes, or 0 if invalid.
 */
size_t pqcp_mlkem_sk_size(pqcp_mlkem_level_t level);

/**
 * @brief Get the ciphertext size for a given security level.
 *
 * @param level The ML-KEM security level.
 * @return Size of the ciphertext in bytes, or 0 if invalid.
 */
size_t pqcp_mlkem_ct_size(pqcp_mlkem_level_t level);

/**
 * @brief Generate an ML-KEM keypair.
 *
 * Generates a fresh ML-KEM keypair using the configured RNG backend.
 *
 * @param level  Security level (PQCP_MLKEM_512, 768, or 1024).
 * @param pk     Output buffer for public key (must be pqcp_mlkem_pk_size(level) bytes).
 * @param sk     Output buffer for secret key (must be pqcp_mlkem_sk_size(level) bytes).
 *
 * @return PQCP_MLKEM_SUCCESS on success, negative error code on failure.
 */
int pqcp_mlkem_keypair(pqcp_mlkem_level_t level, uint8_t *pk, uint8_t *sk);

/**
 * @brief Encapsulate a shared secret using a public key.
 *
 * Generates a random shared secret and encapsulates it for the given public key.
 *
 * @param level  Security level (must match the keypair level).
 * @param pk     Public key (pqcp_mlkem_pk_size(level) bytes).
 * @param ct     Output ciphertext buffer (pqcp_mlkem_ct_size(level) bytes).
 * @param ss     Output shared secret buffer (PQCP_MLKEM_SS_SIZE bytes).
 *
 * @return PQCP_MLKEM_SUCCESS on success, negative error code on failure.
 */
int pqcp_mlkem_encapsulate(pqcp_mlkem_level_t level, const uint8_t *pk,
                           uint8_t *ct, uint8_t *ss);

/**
 * @brief Decapsulate a shared secret using a secret key.
 *
 * Recovers the shared secret from a ciphertext using the secret key.
 * Implements implicit rejection per FIPS-203 to prevent chosen-ciphertext attacks.
 *
 * @param level  Security level (must match the keypair level).
 * @param ct     Ciphertext (pqcp_mlkem_ct_size(level) bytes).
 * @param sk     Secret key (pqcp_mlkem_sk_size(level) bytes).
 * @param ss     Output shared secret buffer (PQCP_MLKEM_SS_SIZE bytes).
 *
 * @return PQCP_MLKEM_SUCCESS on success, negative error code on failure.
 *         Note: Returns success even with invalid ciphertext (implicit rejection).
 */
int pqcp_mlkem_decapsulate(pqcp_mlkem_level_t level, const uint8_t *ct,
                           const uint8_t *sk, uint8_t *ss);

/**
 * @brief Deterministic keypair generation for KAT/testing.
 *
 * Generate a keypair from a known seed. This function is ONLY available
 * when CONFIG_PQCP_RNG_DETERMINISTIC_TEST is enabled.
 *
 * WARNING: Do not use in production! This is for Known Answer Tests only.
 *
 * @param level  Security level.
 * @param seed   Deterministic seed (64 bytes: d || z per FIPS-203).
 * @param pk     Output public key buffer.
 * @param sk     Output secret key buffer.
 *
 * @return PQCP_MLKEM_SUCCESS on success, negative error code on failure.
 */
int pqcp_mlkem_keypair_deterministic(pqcp_mlkem_level_t level,
                                     const uint8_t seed[64],
                                     uint8_t *pk, uint8_t *sk);

/**
 * @brief Deterministic encapsulation for KAT/testing.
 *
 * Encapsulate using a known randomness value. Only available when
 * CONFIG_PQCP_RNG_DETERMINISTIC_TEST is enabled.
 *
 * @param level  Security level.
 * @param pk     Public key.
 * @param coins  Deterministic randomness (32 bytes).
 * @param ct     Output ciphertext buffer.
 * @param ss     Output shared secret buffer.
 *
 * @return PQCP_MLKEM_SUCCESS on success, negative error code on failure.
 */
int pqcp_mlkem_encapsulate_deterministic(pqcp_mlkem_level_t level,
                                         const uint8_t *pk,
                                         const uint8_t coins[32],
                                         uint8_t *ct, uint8_t *ss);

/**
 * @brief Get string name for a security level.
 *
 * @param level The ML-KEM security level.
 * @return String name like "ML-KEM-768", or "Unknown" if invalid.
 */
const char *pqcp_mlkem_level_name(pqcp_mlkem_level_t level);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_MLKEM_H */
