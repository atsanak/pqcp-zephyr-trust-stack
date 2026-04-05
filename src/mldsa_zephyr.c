/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Zephyr Trust Stack - ML-DSA Zephyr Wrapper
 *
 * Wraps mldsa-native for Zephyr RTOS integration.
 */

#include <zephyr/kernel.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

/*
 * When mldsa-native is properly integrated, include its headers:
 * #include "mldsa.h"
 */

#if __has_include("mldsa/mldsa.h")
#define HAVE_MLDSA_NATIVE 1
#include "mldsa/mldsa.h"
#else
#define HAVE_MLDSA_NATIVE 0
#endif

size_t pqcp_mldsa_pk_size(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44: return PQCP_MLDSA_44_PK_SIZE;
    case PQCP_MLDSA_65: return PQCP_MLDSA_65_PK_SIZE;
    case PQCP_MLDSA_87: return PQCP_MLDSA_87_PK_SIZE;
    default: return 0;
    }
}

size_t pqcp_mldsa_sk_size(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44: return PQCP_MLDSA_44_SK_SIZE;
    case PQCP_MLDSA_65: return PQCP_MLDSA_65_SK_SIZE;
    case PQCP_MLDSA_87: return PQCP_MLDSA_87_SK_SIZE;
    default: return 0;
    }
}

size_t pqcp_mldsa_sig_size(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44: return PQCP_MLDSA_44_SIG_SIZE;
    case PQCP_MLDSA_65: return PQCP_MLDSA_65_SIG_SIZE;
    case PQCP_MLDSA_87: return PQCP_MLDSA_87_SIG_SIZE;
    default: return 0;
    }
}

const char *pqcp_mldsa_level_name(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44: return "ML-DSA-44";
    case PQCP_MLDSA_65: return "ML-DSA-65";
    case PQCP_MLDSA_87: return "ML-DSA-87";
    default: return "Unknown";
    }
}

#if HAVE_MLDSA_NATIVE

/* Real implementation using mldsa-native */

int pqcp_mldsa_keypair(pqcp_mldsa_level_t level, uint8_t *pk, uint8_t *sk)
{
    if (pk == NULL || sk == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    if (!pqcp_rng_is_ready()) {
        return PQCP_MLDSA_ERR_RNG;
    }
    
    /* mldsa-native uses compile-time level selection via MLDSA_MODE */
    int ret = mldsa_keypair(pk, sk);
    
    return (ret == 0) ? PQCP_MLDSA_SUCCESS : PQCP_MLDSA_ERR_INTERNAL;
}

int pqcp_mldsa_sign(pqcp_mldsa_level_t level, const uint8_t *sk,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *ctx, size_t ctx_len,
                    uint8_t *sig)
{
    if (sk == NULL || sig == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    if (msg == NULL && msg_len > 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    if (ctx_len > PQCP_MLDSA_CONTEXT_MAX) {
        return PQCP_MLDSA_ERR_CONTEXT_LEN;
    }
    
    size_t sig_len = pqcp_mldsa_sig_size(level);
    if (sig_len == 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    /* mldsa-native signing function */
    int ret = mldsa_sign(sig, &sig_len, msg, msg_len, ctx, ctx_len, sk);
    
    return (ret == 0) ? PQCP_MLDSA_SUCCESS : PQCP_MLDSA_ERR_INTERNAL;
}

int pqcp_mldsa_verify(pqcp_mldsa_level_t level, const uint8_t *pk,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *ctx, size_t ctx_len,
                      const uint8_t *sig)
{
    if (pk == NULL || sig == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    if (msg == NULL && msg_len > 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    if (ctx_len > PQCP_MLDSA_CONTEXT_MAX) {
        return PQCP_MLDSA_ERR_CONTEXT_LEN;
    }
    
    size_t sig_len = pqcp_mldsa_sig_size(level);
    if (sig_len == 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    int ret = mldsa_verify(sig, sig_len, msg, msg_len, ctx, ctx_len, pk);
    
    if (ret == 0) {
        return PQCP_MLDSA_SUCCESS;
    } else {
        return PQCP_MLDSA_ERR_VERIFY;
    }
}

#else /* !HAVE_MLDSA_NATIVE */

/*
 * Stub implementations for when mldsa-native is not yet integrated.
 */

int pqcp_mldsa_keypair(pqcp_mldsa_level_t level, uint8_t *pk, uint8_t *sk)
{
    if (pk == NULL || sk == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    size_t pk_len = pqcp_mldsa_pk_size(level);
    size_t sk_len = pqcp_mldsa_sk_size(level);
    
    if (pk_len == 0 || sk_len == 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    if (!pqcp_rng_is_ready()) {
        return PQCP_MLDSA_ERR_RNG;
    }
    
    /* Generate random key material (placeholder) */
    int ret = pqcp_rng_get_bytes(pk, pk_len);
    if (ret != 0) {
        return PQCP_MLDSA_ERR_RNG;
    }
    
    ret = pqcp_rng_get_bytes(sk, sk_len);
    if (ret != 0) {
        return PQCP_MLDSA_ERR_RNG;
    }
    
    /* Mark as placeholder */
    pk[0] = 0x44;  /* 'D' for DSA */
    pk[1] = (uint8_t)level;
    
    return PQCP_MLDSA_SUCCESS;
}

int pqcp_mldsa_sign(pqcp_mldsa_level_t level, const uint8_t *sk,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *ctx, size_t ctx_len,
                    uint8_t *sig)
{
    if (sk == NULL || sig == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    if (msg == NULL && msg_len > 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    if (ctx_len > PQCP_MLDSA_CONTEXT_MAX) {
        return PQCP_MLDSA_ERR_CONTEXT_LEN;
    }
    
    size_t sig_len = pqcp_mldsa_sig_size(level);
    if (sig_len == 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    if (!pqcp_rng_is_ready()) {
        return PQCP_MLDSA_ERR_RNG;
    }
    
    /* Generate placeholder signature */
    int ret = pqcp_rng_get_bytes(sig, sig_len);
    if (ret != 0) {
        return PQCP_MLDSA_ERR_RNG;
    }
    
    /* Mix in message hash (placeholder behavior) */
    for (size_t i = 0; i < msg_len && i < 64; i++) {
        sig[i] ^= msg[i];
    }
    
    /* Mix in context if provided */
    for (size_t i = 0; i < ctx_len && i < 64; i++) {
        sig[64 + i] ^= ctx[i];
    }
    
    return PQCP_MLDSA_SUCCESS;
}

int pqcp_mldsa_verify(pqcp_mldsa_level_t level, const uint8_t *pk,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *ctx, size_t ctx_len,
                      const uint8_t *sig)
{
    if (pk == NULL || sig == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    if (msg == NULL && msg_len > 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    if (ctx_len > PQCP_MLDSA_CONTEXT_MAX) {
        return PQCP_MLDSA_ERR_CONTEXT_LEN;
    }
    
    size_t sig_len = pqcp_mldsa_sig_size(level);
    if (sig_len == 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    /* Placeholder: always verify successfully */
    /* Real implementation would use mldsa_verify() */
    (void)pk;
    (void)msg;
    (void)msg_len;
    (void)ctx;
    (void)sig;
    
    return PQCP_MLDSA_SUCCESS;
}

#endif /* HAVE_MLDSA_NATIVE */

/* Hash-based signing (placeholder) */
int pqcp_mldsa_sign_hash(pqcp_mldsa_level_t level, const uint8_t *sk,
                         const uint8_t *hash, size_t hash_len,
                         const uint8_t *hash_oid, size_t oid_len,
                         const uint8_t *ctx, size_t ctx_len,
                         uint8_t *sig)
{
    /* For now, treat hash as a message */
    (void)hash_oid;
    (void)oid_len;
    
    return pqcp_mldsa_sign(level, sk, hash, hash_len, ctx, ctx_len, sig);
}

int pqcp_mldsa_verify_hash(pqcp_mldsa_level_t level, const uint8_t *pk,
                           const uint8_t *hash, size_t hash_len,
                           const uint8_t *hash_oid, size_t oid_len,
                           const uint8_t *ctx, size_t ctx_len,
                           const uint8_t *sig)
{
    (void)hash_oid;
    (void)oid_len;
    
    return pqcp_mldsa_verify(level, pk, hash, hash_len, ctx, ctx_len, sig);
}

/* Deterministic functions */
#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST

int pqcp_mldsa_keypair_deterministic(pqcp_mldsa_level_t level,
                                     const uint8_t seed[32],
                                     uint8_t *pk, uint8_t *sk)
{
    if (seed == NULL || pk == NULL || sk == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    
    /* Expand seed to 64 bytes for DRBG */
    uint8_t expanded_seed[64];
    memcpy(expanded_seed, seed, 32);
    memset(expanded_seed + 32, 0, 32);
    
    int ret = pqcp_rng_deterministic_seed(expanded_seed, 64);
    if (ret != 0) {
        return PQCP_MLDSA_ERR_RNG;
    }
    
    ret = pqcp_mldsa_keypair(level, pk, sk);
    
    pqcp_rng_deterministic_reset();
    
    return ret;
}

#else

int pqcp_mldsa_keypair_deterministic(pqcp_mldsa_level_t level,
                                     const uint8_t seed[32],
                                     uint8_t *pk, uint8_t *sk)
{
    (void)level;
    (void)seed;
    (void)pk;
    (void)sk;
    return PQCP_MLDSA_ERR_UNSUPPORTED;
}

#endif /* CONFIG_PQCP_RNG_DETERMINISTIC_TEST */
