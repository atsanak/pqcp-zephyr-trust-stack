/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - ML-DSA baseline wrapper
 *
 * This QEMU-oriented baseline uses a vendored PQClean clean ML-DSA
 * implementation behind the stable Zephyr-facing PQCP ML-DSA API.
 */

#include <zephyr/sys/util.h>

#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

#if defined(CONFIG_PQCP_MLDSA_LEVEL_44) && \
    !defined(CONFIG_PQCP_MLDSA_LEVEL_65) && \
    !defined(CONFIG_PQCP_MLDSA_LEVEL_87)
#include "mldsa44_clean/api.h"
#define PQCP_MLDSA_BASELINE_LEVEL PQCP_MLDSA_44
#define PQCP_MLDSA_BASELINE_SIG_SIZE PQCP_MLDSA_44_SIG_SIZE
#define PQCP_MLDSA_BASELINE_KEYPAIR PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair
#define PQCP_MLDSA_BASELINE_SIGN PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx
#define PQCP_MLDSA_BASELINE_VERIFY PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx
#elif defined(CONFIG_PQCP_MLDSA_LEVEL_65) && \
      !defined(CONFIG_PQCP_MLDSA_LEVEL_44) && \
      !defined(CONFIG_PQCP_MLDSA_LEVEL_87)
#include "mldsa65_clean/api.h"
#define PQCP_MLDSA_BASELINE_LEVEL PQCP_MLDSA_65
#define PQCP_MLDSA_BASELINE_SIG_SIZE PQCP_MLDSA_65_SIG_SIZE
#define PQCP_MLDSA_BASELINE_KEYPAIR PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair
#define PQCP_MLDSA_BASELINE_SIGN PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx
#define PQCP_MLDSA_BASELINE_VERIFY PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx
#elif defined(CONFIG_PQCP_MLDSA_LEVEL_87) && \
      !defined(CONFIG_PQCP_MLDSA_LEVEL_44) && \
      !defined(CONFIG_PQCP_MLDSA_LEVEL_65)
#include "mldsa87_clean/api.h"
#define PQCP_MLDSA_BASELINE_LEVEL PQCP_MLDSA_87
#define PQCP_MLDSA_BASELINE_SIG_SIZE PQCP_MLDSA_87_SIG_SIZE
#define PQCP_MLDSA_BASELINE_KEYPAIR PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair
#define PQCP_MLDSA_BASELINE_SIGN PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx
#define PQCP_MLDSA_BASELINE_VERIFY PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx
#elif defined(__CPPCHECK__)
/*
 * Focused static analysis does not inherit the baseline provider's Kconfig
 * selection, so fall back to one supported single-level mapping there while
 * keeping the real build-time contract strict for compiled configurations.
 */
#include "mldsa65_clean/api.h"
#define PQCP_MLDSA_BASELINE_LEVEL PQCP_MLDSA_65
#define PQCP_MLDSA_BASELINE_SIG_SIZE PQCP_MLDSA_65_SIG_SIZE
#define PQCP_MLDSA_BASELINE_KEYPAIR PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair
#define PQCP_MLDSA_BASELINE_SIGN PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx
#define PQCP_MLDSA_BASELINE_VERIFY PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx
#else
#error "PQCP baseline ML-DSA provider requires a single supported level (44, 65, or 87)"
#endif

static inline int validate_level(pqcp_mldsa_level_t level)
{
    return (level == PQCP_MLDSA_BASELINE_LEVEL) ? 0 : -1;
}

size_t pqcp_mldsa_pk_size(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44:
        return PQCP_MLDSA_44_PK_SIZE;
    case PQCP_MLDSA_65:
        return PQCP_MLDSA_65_PK_SIZE;
    case PQCP_MLDSA_87:
        return PQCP_MLDSA_87_PK_SIZE;
    default:
        return 0U;
    }
}

size_t pqcp_mldsa_sk_size(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44:
        return PQCP_MLDSA_44_SK_SIZE;
    case PQCP_MLDSA_65:
        return PQCP_MLDSA_65_SK_SIZE;
    case PQCP_MLDSA_87:
        return PQCP_MLDSA_87_SK_SIZE;
    default:
        return 0U;
    }
}

size_t pqcp_mldsa_sig_size(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44:
        return PQCP_MLDSA_44_SIG_SIZE;
    case PQCP_MLDSA_65:
        return PQCP_MLDSA_65_SIG_SIZE;
    case PQCP_MLDSA_87:
        return PQCP_MLDSA_87_SIG_SIZE;
    default:
        return 0U;
    }
}

const char *pqcp_mldsa_level_name(pqcp_mldsa_level_t level)
{
    switch (level) {
    case PQCP_MLDSA_44:
        return "ML-DSA-44";
    case PQCP_MLDSA_65:
        return "ML-DSA-65";
    case PQCP_MLDSA_87:
        return "ML-DSA-87";
    default:
        return "Unknown";
    }
}

int pqcp_mldsa_keypair(pqcp_mldsa_level_t level, uint8_t *pk, uint8_t *sk)
{
    if (pk == NULL || sk == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    if (validate_level(level) != 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    if (!pqcp_rng_is_ready()) {
        return PQCP_MLDSA_ERR_RNG;
    }

    return PQCP_MLDSA_BASELINE_KEYPAIR(pk, sk) == 0 ?
        PQCP_MLDSA_SUCCESS : PQCP_MLDSA_ERR_INTERNAL;
}

int pqcp_mldsa_sign(pqcp_mldsa_level_t level, const uint8_t *sk,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *ctx, size_t ctx_len,
                    uint8_t *sig)
{
    size_t sig_len = 0U;
    int ret;

    if (sk == NULL || sig == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    if (msg == NULL && msg_len > 0U) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    if (ctx_len > PQCP_MLDSA_CONTEXT_MAX) {
        return PQCP_MLDSA_ERR_CONTEXT_LEN;
    }
    if (validate_level(level) != 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    if (!pqcp_rng_is_ready()) {
        return PQCP_MLDSA_ERR_RNG;
    }

    ret = PQCP_MLDSA_BASELINE_SIGN(
        sig, &sig_len, msg, msg_len, ctx, ctx_len, sk
    );
    if (ret != 0 || sig_len != PQCP_MLDSA_BASELINE_SIG_SIZE) {
        return PQCP_MLDSA_ERR_INTERNAL;
    }

    return PQCP_MLDSA_SUCCESS;
}

int pqcp_mldsa_verify(pqcp_mldsa_level_t level, const uint8_t *pk,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *ctx, size_t ctx_len,
                      const uint8_t *sig)
{
    int ret;

    if (pk == NULL || sig == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    if (msg == NULL && msg_len > 0U) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }
    if (ctx_len > PQCP_MLDSA_CONTEXT_MAX) {
        return PQCP_MLDSA_ERR_CONTEXT_LEN;
    }
    if (validate_level(level) != 0) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    ret = PQCP_MLDSA_BASELINE_VERIFY(
        sig, PQCP_MLDSA_BASELINE_SIG_SIZE, msg, msg_len, ctx, ctx_len, pk
    );
    return (ret == 0) ? PQCP_MLDSA_SUCCESS : PQCP_MLDSA_ERR_VERIFY;
}

int pqcp_mldsa_sign_hash(pqcp_mldsa_level_t level, const uint8_t *sk,
                         const uint8_t *hash, size_t hash_len,
                         const uint8_t *hash_oid, size_t oid_len,
                         const uint8_t *ctx, size_t ctx_len,
                         uint8_t *sig)
{
    ARG_UNUSED(hash_oid);
    ARG_UNUSED(oid_len);

    return pqcp_mldsa_sign(level, sk, hash, hash_len, ctx, ctx_len, sig);
}

int pqcp_mldsa_verify_hash(pqcp_mldsa_level_t level, const uint8_t *pk,
                           const uint8_t *hash, size_t hash_len,
                           const uint8_t *hash_oid, size_t oid_len,
                           const uint8_t *ctx, size_t ctx_len,
                           const uint8_t *sig)
{
    ARG_UNUSED(hash_oid);
    ARG_UNUSED(oid_len);

    return pqcp_mldsa_verify(level, pk, hash, hash_len, ctx, ctx_len, sig);
}

#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
int pqcp_mldsa_keypair_deterministic(pqcp_mldsa_level_t level,
                                     const uint8_t seed[32],
                                     uint8_t *pk, uint8_t *sk)
{
    uint8_t expanded_seed[64];
    int ret;

    if (seed == NULL || pk == NULL || sk == NULL) {
        return PQCP_MLDSA_ERR_INVALID_ARG;
    }

    memcpy(expanded_seed, seed, 32U);
    memset(expanded_seed + 32U, 0, 32U);

    ret = pqcp_rng_deterministic_seed(expanded_seed, sizeof(expanded_seed));
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
    ARG_UNUSED(level);
    ARG_UNUSED(seed);
    ARG_UNUSED(pk);
    ARG_UNUSED(sk);
    return PQCP_MLDSA_ERR_UNSUPPORTED;
}
#endif
