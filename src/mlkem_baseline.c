/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Zephyr Trust Stack - ML-KEM baseline wrapper
 *
 * This QEMU-oriented baseline uses the vendored PQClean clean ML-KEM-768
 * implementation behind the stable Zephyr-facing PQCP ML-KEM API.
 */

#include <zephyr/sys/util.h>

#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

#include "mlkem768_clean/api.h"

static inline int validate_level(pqcp_mlkem_level_t level)
{
    return (level == PQCP_MLKEM_768) ? 0 : -1;
}

size_t pqcp_mlkem_pk_size(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:
        return PQCP_MLKEM_512_PK_SIZE;
    case PQCP_MLKEM_768:
        return PQCP_MLKEM_768_PK_SIZE;
    case PQCP_MLKEM_1024:
        return PQCP_MLKEM_1024_PK_SIZE;
    default:
        return 0U;
    }
}

size_t pqcp_mlkem_sk_size(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:
        return PQCP_MLKEM_512_SK_SIZE;
    case PQCP_MLKEM_768:
        return PQCP_MLKEM_768_SK_SIZE;
    case PQCP_MLKEM_1024:
        return PQCP_MLKEM_1024_SK_SIZE;
    default:
        return 0U;
    }
}

size_t pqcp_mlkem_ct_size(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:
        return PQCP_MLKEM_512_CT_SIZE;
    case PQCP_MLKEM_768:
        return PQCP_MLKEM_768_CT_SIZE;
    case PQCP_MLKEM_1024:
        return PQCP_MLKEM_1024_CT_SIZE;
    default:
        return 0U;
    }
}

const char *pqcp_mlkem_level_name(pqcp_mlkem_level_t level)
{
    switch (level) {
    case PQCP_MLKEM_512:
        return "ML-KEM-512";
    case PQCP_MLKEM_768:
        return "ML-KEM-768";
    case PQCP_MLKEM_1024:
        return "ML-KEM-1024";
    default:
        return "Unknown";
    }
}

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

    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk) == 0 ?
        PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
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

    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk) == 0 ?
        PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
}

int pqcp_mlkem_decapsulate(pqcp_mlkem_level_t level, const uint8_t *ct,
                           const uint8_t *sk, uint8_t *ss)
{
    if (ct == NULL || sk == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }
    if (validate_level(level) != 0) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }

    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk) == 0 ?
        PQCP_MLKEM_SUCCESS : PQCP_MLKEM_ERR_INTERNAL;
}

#ifdef CONFIG_PQCP_RNG_DETERMINISTIC_TEST
int pqcp_mlkem_keypair_deterministic(pqcp_mlkem_level_t level,
                                     const uint8_t seed[64],
                                     uint8_t *pk, uint8_t *sk)
{
    int ret;

    if (seed == NULL || pk == NULL || sk == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }

    ret = pqcp_rng_deterministic_seed(seed, 64U);
    if (ret != 0) {
        return PQCP_MLKEM_ERR_RNG;
    }

    ret = pqcp_mlkem_keypair(level, pk, sk);
    pqcp_rng_deterministic_reset();
    return ret;
}

int pqcp_mlkem_encapsulate_deterministic(pqcp_mlkem_level_t level,
                                         const uint8_t *pk,
                                         const uint8_t coins[32],
                                         uint8_t *ct, uint8_t *ss)
{
    uint8_t seed[64];
    int ret;

    if (pk == NULL || coins == NULL || ct == NULL || ss == NULL) {
        return PQCP_MLKEM_ERR_INVALID_ARG;
    }

    memcpy(seed, coins, 32U);
    memset(seed + 32U, 0, 32U);

    ret = pqcp_rng_deterministic_seed(seed, sizeof(seed));
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
    ARG_UNUSED(level);
    ARG_UNUSED(seed);
    ARG_UNUSED(pk);
    ARG_UNUSED(sk);
    return PQCP_MLKEM_ERR_UNSUPPORTED;
}

int pqcp_mlkem_encapsulate_deterministic(pqcp_mlkem_level_t level,
                                         const uint8_t *pk,
                                         const uint8_t coins[32],
                                         uint8_t *ct, uint8_t *ss)
{
    ARG_UNUSED(level);
    ARG_UNUSED(pk);
    ARG_UNUSED(coins);
    ARG_UNUSED(ct);
    ARG_UNUSED(ss);
    return PQCP_MLKEM_ERR_UNSUPPORTED;
}
#endif
