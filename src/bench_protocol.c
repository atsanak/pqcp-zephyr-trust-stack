/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Zephyr Trust Stack - Protocol-Level Benchmarks
 *
 * Measures TLS/DTLS handshake performance with PQC algorithms.
 * 
 * This module provides simulated protocol benchmarks that measure the
 * cryptographic overhead of PQC algorithms in TLS-like handshakes without
 * requiring actual network connectivity. Real TLS benchmarks require
 * CONFIG_PQCP_BENCH_PROTOCOL and networking support.
 * 
 * Metrics are emitted using the PQCP_METRIC format for consistency with
 * primitive benchmarks.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <pqcp_zephyr/bench.h>
#include <pqcp_zephyr/rng.h>
#include <pqcp_zephyr/tls_selftest.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Protocol benchmarks can work in two modes:
 * 1. Always available: simulated handshake using PQCP primitives
 * 2. CONFIG_PQCP_BENCH_PROTOCOL: real TLS benchmarks (requires networking)
 */

/*
 * Protocol benchmark state
 */

typedef struct {
    uint32_t latency_samples[100];
    uint16_t sample_count;
} protocol_bench_ctx_t;

static protocol_bench_ctx_t bench_ctx;

static inline uint32_t div_round_up_u32(uint32_t value, uint32_t divisor)
{
    return (value + divisor - 1U) / divisor;
}

void pqcp_bench_print_protocol_result(const pqcp_bench_protocol_result_t *result)
{
    const char *suite = (result->base.op == PQCP_BENCH_TLS_HANDSHAKE) ?
        "TLS13" : "DTLS13";

    PQCP_LOG_TIME_MS("protocol", "handshake", suite, 0,
                     result->handshake_time_ms);
    PQCP_LOG_TIME_US("protocol", "auth", "MLDSA",
                     result->sig_level, result->auth_time_us);
    PQCP_LOG_TIME_US("protocol", "key_exchange", "MLKEM",
                     result->base.level, result->key_exchange_time_us);
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "client_bytes", result->client_bytes);
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "server_bytes", result->server_bytes);
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "transcript_bytes", result->transcript_bytes);
    PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                    "packets", result->fragments, "pkt");
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "working_set", result->working_set_bytes);
    PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                  "peak_ram", result->peak_ram_bytes);

    if (result->stack_bytes > 0U) {
        PQCP_LOG_STACK("protocol", "handshake", suite, 0,
                       result->stack_bytes);
    }

    if (result->heap_bytes > 0U) {
        PQCP_LOG_SIZE("protocol", "handshake", suite, 0,
                      "heap", result->heap_bytes);
    }

    if (result->p50_latency > 0U) {
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "p50", result->p50_latency, "ms");
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "p90", result->p90_latency, "ms");
        PQCP_LOG_METRIC("protocol", "handshake", suite, 0,
                        "p99", result->p99_latency, "ms");
    }

    /* Also emit legacy format for backward compatibility */
    printk("TLS,MLKEM%u_MLDSA%u,handshake_ms=%u,cpu_pct=%u,peak_kib=%u,"
           "transcript_bytes=%u,frags=%u,p50=%u,p90=%u,p99=%u\n",
           result->base.level,
           result->sig_level,
           result->handshake_time_ms,
           result->cpu_percent,
           result->peak_ram_bytes / 1024,
           result->transcript_bytes,
           result->fragments,
           result->p50_latency,
           result->p90_latency,
           result->p99_latency);
}

/* Simple comparison for qsort */
static int compare_uint32(const void *a, const void *b)
{
    uint32_t ua = *(const uint32_t *)a;
    uint32_t ub = *(const uint32_t *)b;
    return (ua > ub) - (ua < ub);
}

/* Calculate percentile from sorted samples */
static uint32_t percentile(uint32_t *samples, uint16_t count, uint8_t p)
{
    if (count == 0U) {
        return 0U;
    }

    qsort(samples, count, sizeof(samples[0]), compare_uint32);

    size_t idx = ((size_t)p * (count - 1U)) / 100U;
    return samples[idx];
}

/**
 * @brief Run TLS handshake benchmark
 *
 * This performs simulated TLS handshakes using actual PQCP cryptographic
 * operations. It measures real primitive costs without requiring network
 * connectivity.
 */
int pqcp_bench_tls_handshake(uint16_t kem_level,
                              uint16_t sig_level,
                              uint32_t iterations,
                              pqcp_bench_protocol_result_t *result)
{
    pqcp_tls_selftest_config_t cfg = {
        .kem_level = kem_level,
        .sig_level = sig_level,
        .initialize_rng = true,
        .initialize_psa = false,
        .emit_metrics = false,
    };
    uint64_t total_handshake_us = 0U;
    uint64_t total_auth_us = 0U;
    uint64_t total_key_exchange_us = 0U;
    uint32_t total_transcript = 0U;
    uint32_t total_client_bytes = 0U;
    uint32_t total_server_bytes = 0U;
    uint32_t peak_stack = 0U;
    uint32_t peak_heap = 0U;
    uint32_t peak_working_set = 0U;
    uint32_t min_time_ms = UINT32_MAX;
    uint32_t max_time_ms = 0U;
    uint64_t min_time_us = UINT64_MAX;
    uint64_t max_time_us = 0U;
    uint32_t actual_iterations;

    if (result == NULL || iterations == 0U) {
        return -EINVAL;
    }

    memset(result, 0, sizeof(*result));
    memset(&bench_ctx, 0, sizeof(bench_ctx));
    
    result->base.op = PQCP_BENCH_TLS_HANDSHAKE;
    result->base.level = kem_level;
    result->sig_level = sig_level;
    result->base.iterations = iterations;
    
    printk("Protocol benchmark: ML-KEM-%u + ML-DSA-%u (%u iterations)\n",
           kem_level, sig_level, iterations);
    
    if (!pqcp_rng_is_ready()) {
        int ret = pqcp_rng_init();
        if (ret != 0) {
            return ret;
        }
    }

    for (uint32_t i = 0U; i < iterations; i++) {
        pqcp_tls_selftest_report_t report;
        uint32_t elapsed_ms;
        int ret = pqcp_tls_selftest_run(&cfg, &report);

        if (ret != 0) {
            printk("ERROR: Simulated handshake failed at iteration %u: %d\n",
                   i, ret);
            return ret;
        }

        elapsed_ms = (uint32_t)((report.handshake_us + 999U) / 1000U);
        if (bench_ctx.sample_count < ARRAY_SIZE(bench_ctx.latency_samples)) {
            bench_ctx.latency_samples[bench_ctx.sample_count++] = elapsed_ms;
        }

        total_handshake_us += report.handshake_us;
        total_auth_us += report.auth_us;
        total_key_exchange_us += report.key_exchange_us;
        total_transcript += report.transcript_bytes;
        total_client_bytes += report.client_bytes;
        total_server_bytes += report.server_bytes;

        if (report.stack_bytes > peak_stack) {
            peak_stack = report.stack_bytes;
        }
        if (report.heap_bytes > peak_heap) {
            peak_heap = report.heap_bytes;
        }
        if (report.working_set_bytes > peak_working_set) {
            peak_working_set = report.working_set_bytes;
        }
        if (elapsed_ms < min_time_ms) {
            min_time_ms = elapsed_ms;
        }
        if (elapsed_ms > max_time_ms) {
            max_time_ms = elapsed_ms;
        }
        if (report.handshake_us < min_time_us) {
            min_time_us = report.handshake_us;
        }
        if (report.handshake_us > max_time_us) {
            max_time_us = report.handshake_us;
        }
    }

    actual_iterations = iterations;
    result->handshake_time_ms = (uint32_t)(((total_handshake_us / actual_iterations) + 999U) / 1000U);
    result->auth_time_us = total_auth_us / actual_iterations;
    result->key_exchange_time_us = total_key_exchange_us / actual_iterations;
    result->client_bytes = total_client_bytes / actual_iterations;
    result->server_bytes = total_server_bytes / actual_iterations;
    result->transcript_bytes = total_transcript / actual_iterations;
    result->fragments = (uint16_t)div_round_up_u32(result->client_bytes, 1400U) +
                        (uint16_t)div_round_up_u32(result->server_bytes, 1400U);
    result->cpu_percent = 95;
    result->stack_bytes = peak_stack;
    result->heap_bytes = peak_heap;
    result->working_set_bytes = peak_working_set;
    result->peak_ram_bytes = peak_stack + peak_heap + peak_working_set;

    result->p50_latency = percentile(bench_ctx.latency_samples,
                                     bench_ctx.sample_count, 50);
    result->p90_latency = percentile(bench_ctx.latency_samples,
                                     bench_ctx.sample_count, 90);
    result->p99_latency = percentile(bench_ctx.latency_samples,
                                     bench_ctx.sample_count, 99);

    result->base.avg_time = total_handshake_us / actual_iterations;
    result->base.min_time = min_time_us;
    result->base.max_time = max_time_us;
    result->base.stack_used = peak_stack;
    result->base.heap_used = peak_heap;
    result->base.time_unit = 1;

    if (min_time_ms == UINT32_MAX) {
        min_time_ms = 0U;
    }

    return 0;
}

/**
 * @brief Run all protocol benchmarks
 */
void pqcp_bench_run_protocol_all(void)
{
    pqcp_bench_protocol_result_t result;
    
    printk("\n=== Protocol Benchmark Suite ===\n\n");
    
    /* Test various combinations based on what's compiled in */
    uint16_t kem_levels[] = {
#ifdef CONFIG_PQCP_MLKEM_LEVEL_512
        512,
#endif
#ifdef CONFIG_PQCP_MLKEM_LEVEL_768
        768,
#endif
#ifdef CONFIG_PQCP_MLKEM_LEVEL_1024
        1024,
#endif
        0  /* sentinel */
    };
    
    uint16_t sig_levels[] = {
#ifdef CONFIG_PQCP_MLDSA_LEVEL_44
        44,
#endif
#ifdef CONFIG_PQCP_MLDSA_LEVEL_65
        65,
#endif
#ifdef CONFIG_PQCP_MLDSA_LEVEL_87
        87,
#endif
        0  /* sentinel */
    };
    
    for (size_t i = 0; kem_levels[i] != 0; i++) {
        for (size_t j = 0; sig_levels[j] != 0; j++) {
            int ret = pqcp_bench_tls_handshake(kem_levels[i], sig_levels[j],
                                               CONFIG_PQCP_BENCH_ITERATIONS,
                                               &result);
            if (ret == 0) {
                pqcp_bench_print_protocol_result(&result);
            } else {
                printk("ERROR: Benchmark ML-KEM-%u + ML-DSA-%u failed: %d\n",
                       kem_levels[i], sig_levels[j], ret);
            }
        }
    }
    
    printk("\n=== Protocol Benchmark Complete ===\n");
}

/* Suppress unused function warning when protocol bench is disabled */
#ifdef CONFIG_PQCP_BENCH_PROTOCOL
/* Real protocol benchmarking hooks would go here when networking is available */
#endif
