/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Zephyr Trust Stack - Shared TLS Self-Test Helpers
 */

#include <pqcp_zephyr/tls_selftest.h>

#include <pqcp_zephyr/bench.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

#include <zephyr/kernel.h>

#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C
#include <psa/crypto.h>
#endif

#include <errno.h>
#include <string.h>

#define PQCP_TLS_SELFTEST_MTU_BYTES          1400U
#define PQCP_TLS_SELFTEST_CLIENTHELLO_BYTES   128U
#define PQCP_TLS_SELFTEST_SERVERHELLO_BYTES   128U

static uint8_t kem_pk[PQCP_MLKEM_PK_SIZE_MAX];
static uint8_t kem_sk[PQCP_MLKEM_SK_SIZE_MAX];
static uint8_t kem_ct[PQCP_MLKEM_CT_SIZE_MAX];
static uint8_t kem_ss_client[PQCP_MLKEM_SS_SIZE];
static uint8_t kem_ss_server[PQCP_MLKEM_SS_SIZE];

static uint8_t sig_pk[PQCP_MLDSA_PK_SIZE_MAX];
static uint8_t sig_sk[PQCP_MLDSA_SK_SIZE_MAX];
static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];

static const uint8_t tls_transcript[] = "TLS 1.3 PQCP self-test transcript";

static inline uint64_t timer_start(void)
{
    return k_cycle_get_64();
}

static inline uint64_t timer_elapsed_us(uint64_t start)
{
    return k_cyc_to_us_floor64(k_cycle_get_64() - start);
}

static inline uint32_t div_round_up_u32(uint32_t value, uint32_t divisor)
{
    return (value + divisor - 1U) / divisor;
}

static pqcp_mlkem_level_t to_mlkem_level(uint16_t level)
{
    switch (level) {
    case 512:
        return PQCP_MLKEM_512;
    case 768:
        return PQCP_MLKEM_768;
    case 1024:
        return PQCP_MLKEM_1024;
    default:
        return (pqcp_mlkem_level_t)-1;
    }
}

static pqcp_mldsa_level_t to_mldsa_level(uint16_t level)
{
    switch (level) {
    case 44:
        return PQCP_MLDSA_44;
    case 65:
        return PQCP_MLDSA_65;
    case 87:
        return PQCP_MLDSA_87;
    default:
        return (pqcp_mldsa_level_t)-1;
    }
}

static uint32_t current_stack_usage(void)
{
#if defined(CONFIG_THREAD_STACK_INFO) && defined(CONFIG_INIT_STACKS)
    struct k_thread *thread = k_current_get();
    size_t unused = 0U;

    if (k_thread_stack_space_get(thread, &unused) == 0) {
        return (uint32_t)(thread->stack_info.size - unused);
    }
#endif

    return 0U;
}

static uint32_t working_set_bytes(pqcp_mlkem_level_t mlkem, pqcp_mldsa_level_t mldsa)
{
    return (uint32_t)(
        pqcp_mlkem_pk_size(mlkem) +
        pqcp_mlkem_sk_size(mlkem) +
        pqcp_mlkem_ct_size(mlkem) +
        (2U * PQCP_MLKEM_SS_SIZE) +
        pqcp_mldsa_pk_size(mldsa) +
        pqcp_mldsa_sk_size(mldsa) +
        pqcp_mldsa_sig_size(mldsa));
}

int pqcp_tls_selftest_init_psa(bool *ready)
{
#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C
    uint8_t random_bytes[32];
    psa_status_t status = psa_crypto_init();

    if (status != PSA_SUCCESS) {
        if (ready != NULL) {
            *ready = false;
        }
        return -EIO;
    }

    status = psa_generate_random(random_bytes, sizeof(random_bytes));
    if (status != PSA_SUCCESS) {
        if (ready != NULL) {
            *ready = false;
        }
        return -EIO;
    }

    if (ready != NULL) {
        *ready = true;
    }

    return 0;
#else
    if (ready != NULL) {
        *ready = false;
    }

    return -ENOTSUP;
#endif
}

int pqcp_tls_selftest_run(const pqcp_tls_selftest_config_t *config,
                          pqcp_tls_selftest_report_t *report)
{
    pqcp_tls_selftest_config_t cfg = config != NULL ?
        *config : (pqcp_tls_selftest_config_t)PQCP_TLS_SELFTEST_CONFIG_DEFAULT;
    pqcp_mlkem_level_t mlkem;
    pqcp_mldsa_level_t mldsa;
    uint64_t handshake_start;
    uint64_t stage_start;
    int ret;

    if (report == NULL) {
        return -EINVAL;
    }

    memset(report, 0, sizeof(*report));
    report->kem_level = cfg.kem_level;
    report->sig_level = cfg.sig_level;

    mlkem = to_mlkem_level(cfg.kem_level);
    mldsa = to_mldsa_level(cfg.sig_level);
    if ((int)mlkem < 0 || (int)mldsa < 0) {
        return -EINVAL;
    }

    if (cfg.initialize_rng && !pqcp_rng_is_ready()) {
        ret = pqcp_rng_init();
        if (ret != 0) {
            return ret;
        }
    }

    if (cfg.initialize_psa) {
        ret = pqcp_tls_selftest_init_psa(&report->psa_ready);
        if (ret != 0) {
            return ret;
        }
    }

    handshake_start = timer_start();

    stage_start = timer_start();
    ret = pqcp_mldsa_keypair(mldsa, sig_pk, sig_sk);
    report->sig_keygen_us = timer_elapsed_us(stage_start);
    if (ret != PQCP_MLDSA_SUCCESS) {
        return -EIO;
    }

    stage_start = timer_start();
    ret = pqcp_mlkem_keypair(mlkem, kem_pk, kem_sk);
    report->kem_keygen_us = timer_elapsed_us(stage_start);
    if (ret != PQCP_MLKEM_SUCCESS) {
        return -EIO;
    }

    stage_start = timer_start();
    ret = pqcp_mldsa_sign(mldsa, sig_sk, tls_transcript,
                          sizeof(tls_transcript) - 1U, NULL, 0U, sig);
    report->sig_sign_us = timer_elapsed_us(stage_start);
    if (ret != PQCP_MLDSA_SUCCESS) {
        return -EIO;
    }

    stage_start = timer_start();
    ret = pqcp_mldsa_verify(mldsa, sig_pk, tls_transcript,
                            sizeof(tls_transcript) - 1U, NULL, 0U, sig);
    report->sig_verify_us = timer_elapsed_us(stage_start);
    if (ret != PQCP_MLDSA_SUCCESS) {
        return -EIO;
    }

    stage_start = timer_start();
    ret = pqcp_mlkem_encapsulate(mlkem, kem_pk, kem_ct, kem_ss_client);
    report->kem_encaps_us = timer_elapsed_us(stage_start);
    if (ret != PQCP_MLKEM_SUCCESS) {
        return -EIO;
    }

    stage_start = timer_start();
    ret = pqcp_mlkem_decapsulate(mlkem, kem_ct, kem_sk, kem_ss_server);
    report->kem_decaps_us = timer_elapsed_us(stage_start);
    if (ret != PQCP_MLKEM_SUCCESS) {
        return -EIO;
    }

    if (memcmp(kem_ss_client, kem_ss_server, PQCP_MLKEM_SS_SIZE) != 0) {
        return -EIO;
    }

    report->auth_us = report->sig_keygen_us +
                      report->sig_sign_us +
                      report->sig_verify_us;
    report->key_exchange_us = report->kem_keygen_us +
                              report->kem_encaps_us +
                              report->kem_decaps_us;
    report->handshake_us = timer_elapsed_us(handshake_start);

    report->client_bytes = PQCP_TLS_SELFTEST_CLIENTHELLO_BYTES +
                           (uint32_t)pqcp_mlkem_ct_size(mlkem);
    report->server_bytes = PQCP_TLS_SELFTEST_SERVERHELLO_BYTES +
                           (uint32_t)pqcp_mlkem_pk_size(mlkem) +
                           (uint32_t)pqcp_mldsa_pk_size(mldsa) +
                           (uint32_t)pqcp_mldsa_sig_size(mldsa);
    report->transcript_bytes = report->client_bytes + report->server_bytes;
    report->packets = (uint16_t)(
        div_round_up_u32(report->client_bytes, PQCP_TLS_SELFTEST_MTU_BYTES) +
        div_round_up_u32(report->server_bytes, PQCP_TLS_SELFTEST_MTU_BYTES));
    report->working_set_bytes = working_set_bytes(mlkem, mldsa);
    report->stack_bytes = current_stack_usage();
    report->heap_bytes = 0U;

    if (cfg.emit_metrics) {
        pqcp_tls_selftest_log_metrics(report);
    }

    return 0;
}

void pqcp_tls_selftest_log_metrics(const pqcp_tls_selftest_report_t *report)
{
    if (report == NULL) {
        return;
    }

    PQCP_LOG_TIME_US("driver", "keygen", "MLKEM",
                     report->kem_level, report->kem_keygen_us);
    PQCP_LOG_TIME_US("driver", "encaps", "MLKEM",
                     report->kem_level, report->kem_encaps_us);
    PQCP_LOG_TIME_US("driver", "decaps", "MLKEM",
                     report->kem_level, report->kem_decaps_us);
    PQCP_LOG_STATUS("driver", "selftest", "MLKEM", report->kem_level, 1);

    PQCP_LOG_TIME_US("driver", "keygen", "MLDSA",
                     report->sig_level, report->sig_keygen_us);
    PQCP_LOG_TIME_US("driver", "sign", "MLDSA",
                     report->sig_level, report->sig_sign_us);
    PQCP_LOG_TIME_US("driver", "verify", "MLDSA",
                     report->sig_level, report->sig_verify_us);
    PQCP_LOG_STATUS("driver", "selftest", "MLDSA", report->sig_level, 1);

    PQCP_LOG_TIME_US("protocol", "auth", "MLDSA",
                     report->sig_level, report->auth_us);
    PQCP_LOG_TIME_US("protocol", "key_exchange", "MLKEM",
                     report->kem_level, report->key_exchange_us);
    PQCP_LOG_TIME_US("protocol", "handshake", "TLS13", 0,
                     report->handshake_us);
    PQCP_LOG_SIZE("protocol", "handshake", "TLS13", 0,
                  "client_bytes", report->client_bytes);
    PQCP_LOG_SIZE("protocol", "handshake", "TLS13", 0,
                  "server_bytes", report->server_bytes);
    PQCP_LOG_SIZE("protocol", "handshake", "TLS13", 0,
                  "transcript_bytes", report->transcript_bytes);
    PQCP_LOG_METRIC("protocol", "handshake", "TLS13", 0,
                    "packets", report->packets, "pkt");
    PQCP_LOG_SIZE("protocol", "handshake", "TLS13", 0,
                  "working_set", report->working_set_bytes);

    if (report->stack_bytes > 0U) {
        PQCP_LOG_STACK("protocol", "handshake", "TLS13", 0,
                       report->stack_bytes);
    }

    if (report->heap_bytes > 0U) {
        PQCP_LOG_SIZE("protocol", "handshake", "TLS13", 0,
                      "heap", report->heap_bytes);
    }

    PQCP_LOG_STATUS("protocol", "handshake", "TLS13", 0, 1);
}
