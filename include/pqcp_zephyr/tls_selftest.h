/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Zephyr Trust Stack - TLS Self-Test Helpers
 *
 * Shared self-test and protocol benchmarking helpers for exercising the
 * PQCP TLS/PSA integration path without requiring live networking.
 */

#ifndef PQCP_ZEPHYR_TLS_SELFTEST_H_
#define PQCP_ZEPHYR_TLS_SELFTEST_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pqcp_tls_selftest_config {
    uint16_t kem_level;
    uint16_t sig_level;
    bool initialize_rng;
    bool initialize_psa;
    bool emit_metrics;
} pqcp_tls_selftest_config_t;

typedef struct pqcp_tls_selftest_report {
    uint16_t kem_level;
    uint16_t sig_level;

    uint64_t kem_keygen_us;
    uint64_t kem_encaps_us;
    uint64_t kem_decaps_us;
    uint64_t sig_keygen_us;
    uint64_t sig_sign_us;
    uint64_t sig_verify_us;

    uint64_t auth_us;
    uint64_t key_exchange_us;
    uint64_t handshake_us;
    uint64_t provider_overhead_us;

    uint32_t client_bytes;
    uint32_t server_bytes;
    uint32_t transcript_bytes;
    uint32_t certificate_bytes;
    uint32_t key_exchange_bytes;
    uint32_t transport_overhead_bytes;
    uint16_t packets;

    uint32_t working_set_bytes;
    uint32_t stack_bytes;
    uint32_t heap_bytes;
    bool psa_ready;
} pqcp_tls_selftest_report_t;

#define PQCP_TLS_SELFTEST_CONFIG_DEFAULT { \
    .kem_level = 768, \
    .sig_level = 65, \
    .initialize_rng = true, \
    .initialize_psa = false, \
    .emit_metrics = true, \
}

/**
 * @brief Shared TLS self-test configuration.
 *
 * `kem_level` and `sig_level` must match levels compiled into the current
 * image. `initialize_rng` and `initialize_psa` allow callers to exercise the
 * harness either as a self-contained smoke test or inside a larger benchmark
 * flow where setup already happened earlier.
 *
 * This API is intended for offline self-test, benchmark, and CI coverage
 * flows. It is not a replacement for a production TLS session manager.
 */

/**
 * @brief Structured report produced by the TLS self-test harness.
 *
 * Timing fields are reported in microseconds. Byte counters capture the
 * synthetic client/server payload sizes and derived transcript size used by
 * the offline TLS benchmark path. `provider_overhead_us` is the residual
 * handshake time after subtracting the direct ML-KEM and ML-DSA stage costs,
 * which makes it easier to separate primitive cost from the surrounding
 * framework state machine when analyzing protocol metrics.
 *
 * `certificate_bytes`, `key_exchange_bytes`, and
 * `transport_overhead_bytes` provide a lightweight handshake size
 * decomposition without changing the stable PQCP_METRIC wire format.
 * Memory fields reflect best-effort working set and stack observations
 * available in the current build.
 *
 * The report structure is shared by the TLS sample, protocol benchmark sample,
 * and ztest coverage so those paths stay aligned on metric names and meaning.
 */

/**
 * @brief Initialize PSA crypto for TLS self-tests.
 *
 * When PSA support is not compiled in, the function returns -ENOTSUP.
 *
 * @param ready Optional pointer that receives whether PSA was initialized.
 *
 * @return 0 on success, negative errno-style code on failure.
 *
 * @note Intended for both test/benchmark harnesses and production-oriented
 *       integrations that want to probe PSA availability before calling the
 *       shared TLS self-test flow.
 */
int pqcp_tls_selftest_init_psa(bool *ready);

/**
 * @brief Run the shared PQCP TLS self-test flow.
 *
 * This performs the same PQC-heavy operations used by the TLS sample's
 * self-test mode: ML-DSA key generation/sign/verify and ML-KEM
 * key generation/encaps/decaps, plus transcript and payload accounting.
 *
 * Callers typically use this in one of two ways:
 *
 * - TLS sample self-test mode, with `initialize_rng=true`,
 *   `initialize_psa=true`, and `emit_metrics=true`
 * - Protocol benchmark/sample mode, with setup handled externally and
 *   `emit_metrics` controlled by the benchmark harness
 *
 * @param config Benchmark/self-test configuration. NULL uses defaults.
 * @param report Output report filled on success.
 *
 * @retval 0 Self-test flow completed successfully.
 * @retval -EINVAL Invalid pointers or unsupported algorithm levels.
 * @retval -ENOTSUP PSA initialization was requested in a build without PSA.
 * @retval Other negative errno-style codes propagated from RNG or PSA setup.
 * @retval -EIO One of the underlying PQCP operations failed or produced
 *         mismatched shared secrets.
 *
 * @note Intended for both reusable test/benchmark harnesses and sample code
 *       paths that want a shared offline TLS/PSA/PQCP validation flow.
 */
int pqcp_tls_selftest_run(const pqcp_tls_selftest_config_t *config,
                          pqcp_tls_selftest_report_t *report);

/**
 * @brief Emit structured metrics for a completed TLS self-test run.
 *
 * Metric emission preserves the stable eight-field `PQCP_METRIC` wire format
 * used across the module. The harness only adds new metric names and does not
 * alter the field layout.
 *
 * @param report Completed report to log.
 *
 * @note Intended for test/benchmark harnesses and sample code paths that emit
 *       structured metrics for later parsing.
 */
void pqcp_tls_selftest_log_metrics(const pqcp_tls_selftest_report_t *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_TLS_SELFTEST_H_ */
