/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Zephyr Trust Stack - ML-KEM Zephyr Wrapper
 *
 * Wraps mlkem-native for Zephyr RTOS integration.
 */

#include <zephyr/kernel.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

/*
 * When mlkem-native is properly integrated, include its headers:
 * #include "mlkem.h"
 * 
 * For now, we provide stub implementations that will be replaced
 * once the submodule is added.
 */

/* Check if we have the real mlkem-native */
#if __has_include("mlkem/mlkem.h")
#define HAVE_MLKEM_NATIVE 1
#include "mlkem/mlkem.h"
#else
#define HAVE_MLKEM_NATIVE 0
#endif

/* Size lookup tables */
static const size_t pk_sizes[] = {
    [0] = 0,
    [512] = PQCP_MLKEM_512_PK_SIZE,
    [768] = PQCP_MLKEM_768_PK_SIZE,
    [1024] = PQCP_MLKEM_1024_PK_SIZE,
};

static const size_t sk_sizes[] = {
    [0] = 0,
    [512] = PQCP_MLKEM_512_SK_SIZE,
    [768] = PQCP_MLKEM_768_SK_SIZE,
    [1024] = PQCP_MLKEM_1024_SK_SIZE,
};

static const size_t ct_sizes[] = {
    [0] = 0,
    [512] = PQCP_MLKEM_512_CT_SIZE,
    [768] = PQCP_MLKEM_768_CT_SIZE,
    [1024] = PQCP_MLKEM_1024_CT_SIZE,
};

static inline int level_to_index(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return 512;
    case PQCP_MLKEM_768:  return 768;
    case PQCP_MLKEM_1024: return 1024;
    default: return 0;
    }
}

size_t pqcp_mlkem_pk_size(pqcp_mlkem_level_t level)
{
    int idx = level_to_index(level);
    if (idx == 0) return 0;
    
    /* Map level value to array index */
    switch (level) {
    case PQCP_MLKEM_512:  return PQCP_MLKEM_512_PK_SIZE;
    case PQCP_MLKEM_768:  return PQCP_MLKEM_768_PK_SIZE;
    case PQCP_MLKEM_1024: return PQCP_MLKEM_1024_PK_SIZE;
    default: return 0;
    }
}

size_t pqcp_mlkem_sk_size(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return PQCP_MLKEM_512_SK_SIZE;
    case PQCP_MLKEM_768:  return PQCP_MLKEM_768_SK_SIZE;
    case PQCP_MLKEM_1024: return PQCP_MLKEM_1024_SK_SIZE;
    default: return 0;
    }
}

size_t pqcp_mlkem_ct_size(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return PQCP_MLKEM_512_CT_SIZE;
    case PQCP_MLKEM_768:  return PQCP_MLKEM_768_CT_SIZE;
    case PQCP_MLKEM_1024: return PQCP_MLKEM_1024_CT_SIZE;
    default: return 0;
    }
}

const char *pqcp_mlkem_level_name(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return "ML-KEM-512";
    case PQCP_MLKEM_768:  return "ML-KEM-768";
    case PQCP_MLKEM_1024: return "ML-KEM-1024";
    default: return "Unknown";
    }
}

#if HAVE_MLKEM_NATIVE

/* Real implementation using mlkem-native */

int pqcp_mlkem_keypair(pqcp_mlkem_level_t level, uint8_t *pk, uint8_t *sk)
{
    if (pk == NULL || sk == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    if (!pqcp_rng_is_ready()) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    /* mlkem-native uses compile-time level selection via MLKEM_K */
    /* The actual call depends on how mlkem-native is configured */
    
    int ret = mlkem_keypair(pk, sk);
    
    return (ret == 0) ? PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
}

int pqcp_mlkem_encapsulate(pqcp_mlkem_level_t level, const uint8_t *pk,
                           uint8_t *ct, uint8_t *ss)
{
    if (pk == NULL || ct == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    if (!pqcp_rng_is_ready()) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    int ret = mlkem_enc(ct, ss, pk);
    
    return (ret == 0) ? PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
}

int pqcp_mlkem_decapsulate(pqcp_mlkem_level_t level, const uint8_t *ct,
                           const uint8_t *sk, uint8_t *ss)
{
    if (ct == NULL || sk == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    int ret = mlkem_dec(ss, ct, sk);
    
    /* ML-KEM uses implicit rejection - always returns success */
    return (ret == 0) ? PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
}

#else /* !HAVE_MLKEM_NATIVE */

/*
 * Stub implementations for when mlkem-native is not yet integrated.
 * These allow the module to build and test basic integration.
 */

int pqcp_mlkem_keypair(pqcp_mlkem_level_t level, uint8_t *pk, uint8_t *sk)
{
    if (pk == NULL || sk == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    size_t pk_len = pqcp_mlkem_pk_size(level);
    size_t sk_len = pqcp_mlkem_sk_size(level);
    
    if (pk_len == 0 || sk_len == 0) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    if (!pqcp_rng_is_ready()) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    /* Generate random key material (placeholder) */
    int ret = pqcp_rng_get_bytes(pk, pk_len);
    if (ret != 0) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    ret = pqcp_rng_get_bytes(sk, sk_len);
    if (ret != 0) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    /* Mark as placeholder with pattern */
    pk[0] = 0x4B;  /* 'K' for KEM */
    pk[1] = (uint8_t)(level >> 8);
    pk[2] = (uint8_t)(level & 0xFF);
    
    return PQCP_MLKEM_SUCCESS;
}

int pqcp_mlkem_encapsulate(pqcp_mlkem_level_t level, const uint8_t *pk,
                           uint8_t *ct, uint8_t *ss)
{
    if (pk == NULL || ct == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    size_t ct_len = pqcp_mlkem_ct_size(level);
    
    if (ct_len == 0) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    if (!pqcp_rng_is_ready()) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    /* Generate random ciphertext and shared secret (placeholder) */
    int ret = pqcp_rng_get_bytes(ct, ct_len);
    if (ret != 0) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    ret = pqcp_rng_get_bytes(ss, PQCP_MLKEM_SS_SIZE);
    if (ret != 0) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    return PQCP_MLKEM_SUCCESS;
}

int pqcp_mlkem_decapsulate(pqcp_mlkem_level_t level, const uint8_t *ct,
                           const uint8_t *sk, uint8_t *ss)
{
    if (ct == NULL || sk == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    /* Generate deterministic shared secret from sk hash (placeholder) */
    /* In real implementation, this is implicit rejection */
    for (int i = 0; i < PQCP_MLKEM_SS_SIZE; i++) {
        ss[i] = sk[i % 32] ^ ct[i % 32] ^ 0xAA;
    }
    
    return PQCP_MLKEM_SUCCESS;
}

#endif /* HAVE_MLKEM_NATIVE */

/* Deterministic functions - only when test mode enabled */
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST

int pqcp_mlkem_keypair_deterministic(pqcp_mlkem_level_t level,
                                     const uint8_t seed[64],
                                     uint8_t *pk, uint8_t *sk)
{
    if (seed == NULL || pk == NULL || sk == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    /* Seed the deterministic RNG */
    int ret = pqcp_rng_deterministic_seed(seed, 64);
    if (ret != 0) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    /* Generate keypair using deterministic RNG */
    ret = pqcp_mlkem_keypair(level, pk, sk);
    
    /* Reset RNG after use */
    pqcp_rng_deterministic_reset();
    
    return ret;
}

int pqcp_mlkem_encapsulate_deterministic(pqcp_mlkem_level_t level,
                                         const uint8_t *pk,
                                         const uint8_t coins[32],
                                         uint8_t *ct, uint8_t *ss)
{
    if (pk == NULL || coins == NULL || ct == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    /* Use coins as RNG seed */
    uint8_t seed[64];
    memcpy(seed, coins, 32);
    memset(seed + 32, 0, 32);
    
    int ret = pqcp_rng_deterministic_seed(seed, 64);
    if (ret != 0) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    ret = pqcp_mlkem_encapsulate(level, pk, ct, ss);
    
    pqcp_rng_deterministic_reset();
    
    return ret;
}

#else

int pqcp_mlkem_keypair_deterministic(pqcp_mlkem_level_t level,
                                     const uint8_t seed[64],
                                     uint8_t *pk, uint8_t *sk)
{
    (void)level;
    (void)seed;
    (void)pk;
    (void)sk;
    return PQCP_MLKEM_ERR_UNSUPPORTED;
}

int pqcp_mlkem_encapsulate_deterministic(pqcp_mlkem_level_t level,
                                         const uint8_t *pk,
                                         const uint8_t coins[32],
                                         uint8_t *ct, uint8_t *ss)
{
    (void)level;
    (void)pk;
    (void)coins;
    (void)ct;
    (void)ss;
    return PQCP_MLKEM_ERR_UNSUPPORTED;
}

#endif /* CONFIG_PQCP_RNG_DETERMINISTIC_TEST */
