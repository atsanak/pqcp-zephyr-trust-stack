/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - ML-KEM Zephyr Wrapper
 *
 * Wraps mlkem-native for Zephyr RTOS integration.
 */

#include <zephyr/kernel.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

/* Check if we have the real mlkem-native */
#if defined(PQCP_MLKEM_MULTILEVEL_BUILD)
#define HAVE_MLKEM_NATIVE 1
#include "mlkem_native_all.h"
#elif __has_include("mlkem_native.h")
#define HAVE_MLKEM_NATIVE 1
#include "mlkem_native.h"
#elif __has_include("mlkem/mlkem_native.h")
#define HAVE_MLKEM_NATIVE 1
#include "mlkem/mlkem_native.h"
#else
#error "mlkem-native headers not found. Run ext/setup_libs.py first."
#endif

/* Validate the requested level matches the compiled level */
static inline int validate_level(pqcp_mlkem_level_t level)
{
#if defined(PQCP_MLKEM_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLKEM_512:
        return IS_ENABLED(CONFIG_PQCP_MLKEM_LEVEL_512) ? 0 : -1;
    case PQCP_MLKEM_768:
        return IS_ENABLED(CONFIG_PQCP_MLKEM_LEVEL_768) ? 0 : -1;
    case PQCP_MLKEM_1024:
        return IS_ENABLED(CONFIG_PQCP_MLKEM_LEVEL_1024) ? 0 : -1;
    default:
        return -1;
    }
#else
/*
 * Determine the compile-time configured level from MLK_CONFIG_PARAMETER_SET
 * or fall back to the legacy MLKEM_K definition.
 */
#if defined(MLK_CONFIG_PARAMETER_SET)
#define PQCP_MLKEM_COMPILED_LEVEL MLK_CONFIG_PARAMETER_SET
#elif defined(MLKEM_K)
/* Map MLKEM_K (2,3,4) to parameter set (512,768,1024) */
#if MLKEM_K == 2
#define PQCP_MLKEM_COMPILED_LEVEL 512
#elif MLKEM_K == 3
#define PQCP_MLKEM_COMPILED_LEVEL 768
#elif MLKEM_K == 4
#define PQCP_MLKEM_COMPILED_LEVEL 1024
#else
#error "Invalid MLKEM_K value"
#endif
#else
/* Default to ML-KEM-768 */
#define PQCP_MLKEM_COMPILED_LEVEL 768
#endif
    switch (level) {
    case PQCP_MLKEM_512:
        return (PQCP_MLKEM_COMPILED_LEVEL == 512) ? 0 : -1;
    case PQCP_MLKEM_768:
        return (PQCP_MLKEM_COMPILED_LEVEL == 768) ? 0 : -1;
    case PQCP_MLKEM_1024:
        return (PQCP_MLKEM_COMPILED_LEVEL == 1024) ? 0 : -1;
    default:
        return -1;
    }
#endif
}

size_t pqcp_mlkem_pk_size(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return MLKEM512_PUBLICKEYBYTES;
    case PQCP_MLKEM_768:  return MLKEM768_PUBLICKEYBYTES;
    case PQCP_MLKEM_1024: return MLKEM1024_PUBLICKEYBYTES;
    default: return 0;
    }
}

size_t pqcp_mlkem_sk_size(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return MLKEM512_SECRETKEYBYTES;
    case PQCP_MLKEM_768:  return MLKEM768_SECRETKEYBYTES;
    case PQCP_MLKEM_1024: return MLKEM1024_SECRETKEYBYTES;
    default: return 0;
    }
}

size_t pqcp_mlkem_ct_size(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:  return MLKEM512_CIPHERTEXTBYTES;
    case PQCP_MLKEM_768:  return MLKEM768_CIPHERTEXTBYTES;
    case PQCP_MLKEM_1024: return MLKEM1024_CIPHERTEXTBYTES;
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
    
    if (validate_level(level) != 0) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    if (!pqcp_rng_is_ready()) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    int ret;

#if defined(PQCP_MLKEM_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLKEM_512:
        ret = mlkem512_keypair(pk, sk);
        break;
    case PQCP_MLKEM_768:
        ret = mlkem768_keypair(pk, sk);
        break;
    case PQCP_MLKEM_1024:
        ret = mlkem1024_keypair(pk, sk);
        break;
    default:
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
#else
    /* mlkem-native uses namespaced API: crypto_kem_keypair is a macro
     * that expands to the correct function name based on config */
    ret = crypto_kem_keypair(pk, sk);
#endif

    return (ret == 0) ? PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
}

int pqcp_mlkem_encapsulate(pqcp_mlkem_level_t level, const uint8_t *pk,
                           uint8_t *ct, uint8_t *ss)
{
    if (pk == NULL || ct == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    if (validate_level(level) != 0) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    if (!pqcp_rng_is_ready()) {
        return PQCP_MLKEM_ERR_RNG;
    }
    
    int ret;

#if defined(PQCP_MLKEM_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLKEM_512:
        ret = mlkem512_enc(ct, ss, pk);
        break;
    case PQCP_MLKEM_768:
        ret = mlkem768_enc(ct, ss, pk);
        break;
    case PQCP_MLKEM_1024:
        ret = mlkem1024_enc(ct, ss, pk);
        break;
    default:
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
#else
    ret = crypto_kem_enc(ct, ss, pk);
#endif

    return (ret == 0) ? PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
}

static int mlkem_decapsulate_backend(pqcp_mlkem_level_t level, const uint8_t *ct,
                                     const uint8_t *sk, uint8_t *ss)
{
    if (ct == NULL || sk == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    if (validate_level(level) != 0) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    
    int ret;

#if defined(PQCP_MLKEM_MULTILEVEL_BUILD)
    switch (level) {
    case PQCP_MLKEM_512:
        ret = mlkem512_dec(ss, ct, sk);
        break;
    case PQCP_MLKEM_768:
        ret = mlkem768_dec(ss, ct, sk);
        break;
    case PQCP_MLKEM_1024:
        ret = mlkem1024_dec(ss, ct, sk);
        break;
    default:
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
#else
    ret = crypto_kem_dec(ss, ct, sk);
#endif

    /* ML-KEM uses implicit rejection - always returns success */
    return (ret == 0) ? PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
}


#if defined(CONFIG_PQCP_FAULT_CANARY) || defined(CONFIG_PQCP_FAULT_DUPLICATE)
/* Constant-time equality; 1 when equal. */
static int fault_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0U;

    for (size_t i = 0U; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0U;
}

static void fault_wipe(volatile uint8_t *p, size_t n)
{
    while (n-- > 0U) {
        *p++ = 0U;
    }
}
#endif

#ifdef CONFIG_PQCP_FAULT_CANARY
/*
 * Negative canary: a corrupted ciphertext whose genuine key is known. The
 * genuine key came from encapsulation, not from the decapsulation path under
 * suspicion. A correct decapsulation takes implicit rejection and returns a
 * DIFFERENT key; a defeated Fujisaki-Okamoto check returns the genuine one.
 */
static struct {
    bool ready;
    pqcp_mlkem_level_t level;
    uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    uint8_t bad_ct[PQCP_MLKEM_CT_SIZE_MAX];
    uint8_t genuine[PQCP_MLKEM_SS_SIZE];
} kem_canary;
static K_MUTEX_DEFINE(kem_canary_lock);

static int kem_canary_prepare(pqcp_mlkem_level_t level)
{
    static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    int ret;

    if (kem_canary.ready && kem_canary.level == level) {
        return 0;
    }
    kem_canary.ready = false;
    ret = pqcp_mlkem_keypair(level, pk, kem_canary.sk);
    if (ret != PQCP_MLKEM_SUCCESS) {
        return ret;
    }
    ret = pqcp_mlkem_encapsulate(level, pk, kem_canary.bad_ct,
                                 kem_canary.genuine);
    if (ret != PQCP_MLKEM_SUCCESS) {
        return ret;
    }
    kem_canary.bad_ct[7] ^= 0x81U;
    kem_canary.level = level;
    kem_canary.ready = true;
    return 0;
}

static int kem_canary_ok(pqcp_mlkem_level_t level)
{
    uint8_t out[PQCP_MLKEM_SS_SIZE];
    int ret;
    int equal;

    k_mutex_lock(&kem_canary_lock, K_FOREVER);
    ret = kem_canary_prepare(level);
    if (ret == 0) {
        ret = mlkem_decapsulate_backend(level, kem_canary.bad_ct,
                                        kem_canary.sk, out);
    }
    equal = (ret == 0) && fault_equal(out, kem_canary.genuine,
                                      PQCP_MLKEM_SS_SIZE);
    fault_wipe(out, sizeof(out));
    k_mutex_unlock(&kem_canary_lock);
    /* Preparation or backend errors are not fault evidence. */
    return ret != 0 || !equal;
}
#endif /* CONFIG_PQCP_FAULT_CANARY */

int pqcp_mlkem_decapsulate(pqcp_mlkem_level_t level, const uint8_t *ct,
                           const uint8_t *sk, uint8_t *ss)
{
    int ret = mlkem_decapsulate_backend(level, ct, sk, ss);

#ifdef CONFIG_PQCP_FAULT_DUPLICATE
    if (ret == PQCP_MLKEM_SUCCESS) {
        uint8_t again[PQCP_MLKEM_SS_SIZE];
        int second = mlkem_decapsulate_backend(level, ct, sk, again);

        if (second != PQCP_MLKEM_SUCCESS ||
            !fault_equal(ss, again, PQCP_MLKEM_SS_SIZE)) {
            fault_wipe(ss, PQCP_MLKEM_SS_SIZE);
            ret = PQCP_MLKEM_ERR_FAULT_DETECTED;
        }
        fault_wipe(again, sizeof(again));
    }
#endif
#ifdef CONFIG_PQCP_FAULT_CANARY
    if (ret == PQCP_MLKEM_SUCCESS && !kem_canary_ok(level)) {
        fault_wipe(ss, PQCP_MLKEM_SS_SIZE);
        ret = PQCP_MLKEM_ERR_FAULT_DETECTED;
    }
#endif
    return ret;
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
