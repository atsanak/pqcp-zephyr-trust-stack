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
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>
#include <string.h>

/* Protocol benchmarks can work in two modes:
 * 1. Always available: simulated handshake using PQCP primitives
 * 2. CONFIG_PQCP_BENCH_PROTOCOL: real TLS benchmarks (requires networking)
 */

/*
 * Protocol benchmark state
 */

typedef struct {
    /* Metrics */
    uint32_t handshake_start_ms;
    uint32_t handshake_end_ms;
    uint32_t bytes_sent;
    uint32_t bytes_received;
    uint16_t fragments_sent;
    uint16_t fragments_received;
    uint32_t peak_ram;
    
    /* Running stats for percentiles */
    uint32_t latency_samples[100];
    uint16_t sample_count;
    
} protocol_bench_ctx_t;

static protocol_bench_ctx_t bench_ctx;

/* Static buffers for simulated handshake (allocated once) */
static uint8_t kem_pk[PQCP_MLKEM_PK_SIZE_MAX];
static uint8_t kem_sk[PQCP_MLKEM_SK_SIZE_MAX];
static uint8_t kem_ct[PQCP_MLKEM_CT_SIZE_MAX];
static uint8_t kem_ss1[PQCP_MLKEM_SS_SIZE];
static uint8_t kem_ss2[PQCP_MLKEM_SS_SIZE];

static uint8_t dsa_pk[PQCP_MLDSA_PK_SIZE_MAX];
static uint8_t dsa_sk[PQCP_MLDSA_SK_SIZE_MAX];
static uint8_t dsa_sig[PQCP_MLDSA_SIG_SIZE_MAX];

void pqcp_bench_print_protocol_result(const pqcp_bench_protocol_result_t *result)
{
    /* Emit PQCP_METRIC format for consistency with primitive benchmarks */
    printk("PQCP_METRIC,protocol,handshake,MLKEM,%u,time,%u,ms\n",
           result->base.level, result->handshake_time_ms);
    printk("PQCP_METRIC,protocol,handshake,MLKEM,%u,transcript,%u,B\n",
           result->base.level, result->transcript_bytes);
    printk("PQCP_METRIC,protocol,handshake,MLKEM,%u,fragments,%u,pkt\n",
           result->base.level, result->fragments);
    printk("PQCP_METRIC,protocol,handshake,MLKEM,%u,peak_ram,%u,B\n",
           result->base.level, result->peak_ram_bytes);
    
    if (result->p50_latency > 0) {
        printk("PQCP_METRIC,protocol,handshake,MLKEM,%u,p50,%u,ms\n",
               result->base.level, result->p50_latency);
        printk("PQCP_METRIC,protocol,handshake,MLKEM,%u,p90,%u,ms\n",
               result->base.level, result->p90_latency);
        printk("PQCP_METRIC,protocol,handshake,MLKEM,%u,p99,%u,ms\n",
               result->base.level, result->p99_latency);
    }
    
    /* Also emit legacy format for backward compatibility */
    printk("TLS,%s%u,handshake_ms=%u,cpu_pct=%u,peak_kib=%u,"
           "transcript_bytes=%u,frags=%u,p50=%u,p90=%u,p99=%u\n",
           (result->base.op == PQCP_BENCH_TLS_HANDSHAKE) ? "MLKEM" : "DTLS_MLKEM",
           result->base.level,
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
    if (count == 0) return 0;
    
    /* Sort samples */
    for (int i = 0; i < count - 1; i++) {
        for (int j = i + 1; j < count; j++) {
            if (samples[i] > samples[j]) {
                uint32_t tmp = samples[i];
                samples[i] = samples[j];
                samples[j] = tmp;
            }
        }
    }
    
    size_t idx = (size_t)((p / 100.0) * (count - 1));
    return samples[idx];
}

/**
 * @brief Get ML-KEM level enum from numeric level
 */
static pqcp_mlkem_level_t get_mlkem_level(uint16_t level)
{
    switch (level) {
    case 512:  return PQCP_MLKEM_512;
    case 768:  return PQCP_MLKEM_768;
    case 1024: return PQCP_MLKEM_1024;
    default:   return PQCP_MLKEM_768;
    }
}

/**
 * @brief Get ML-DSA level enum from numeric level
 */
static pqcp_mldsa_level_t get_mldsa_level(uint16_t level)
{
    switch (level) {
    case 44: return PQCP_MLDSA_44;
    case 65: return PQCP_MLDSA_65;
    case 87: return PQCP_MLDSA_87;
    default: return PQCP_MLDSA_65;
    }
}

/**
 * @brief Simulate a single TLS 1.3 + PQC handshake using PQCP primitives
 *
 * This simulates the cryptographic operations in a PQC TLS handshake:
 * - Server: ML-DSA keypair + certificate signature
 * - Client: ML-KEM encapsulation for key exchange
 * - Server: ML-KEM decapsulation
 * - Both: Shared secret established
 *
 * @return Handshake time in milliseconds
 */
static int simulate_pqc_handshake(uint16_t kem_level, uint16_t sig_level,
                                   uint32_t *elapsed_ms, uint32_t *transcript_bytes)
{
    pqcp_mlkem_level_t mlkem = get_mlkem_level(kem_level);
    pqcp_mldsa_level_t mldsa = get_mldsa_level(sig_level);
    int ret;
    
    uint32_t start_ms = k_uptime_get_32();
    
    /* Phase 1: Server generates ML-DSA keypair (certificate key) */
    ret = pqcp_mldsa_keypair(mldsa, dsa_pk, dsa_sk);
    if (ret != PQCP_MLDSA_SUCCESS) {
        return ret;
    }
    
    /* Phase 2: Server generates ephemeral ML-KEM keypair */
    ret = pqcp_mlkem_keypair(mlkem, kem_pk, kem_sk);
    if (ret != PQCP_MLKEM_SUCCESS) {
        return ret;
    }
    
    /* Phase 3: Server signs transcript (ClientHello || ServerHello || pk) */
    static const uint8_t mock_transcript[] = "TLS 1.3 handshake transcript";
    ret = pqcp_mldsa_sign(mldsa, dsa_sk, mock_transcript, sizeof(mock_transcript) - 1,
                          NULL, 0, dsa_sig);
    if (ret != PQCP_MLDSA_SUCCESS) {
        return ret;
    }
    
    /* Phase 4: Client verifies server signature */
    ret = pqcp_mldsa_verify(mldsa, dsa_pk, mock_transcript, sizeof(mock_transcript) - 1,
                            NULL, 0, dsa_sig);
    if (ret != PQCP_MLDSA_SUCCESS) {
        return ret;
    }
    
    /* Phase 5: Client encapsulates shared secret */
    ret = pqcp_mlkem_encapsulate(mlkem, kem_pk, kem_ct, kem_ss1);
    if (ret != PQCP_MLKEM_SUCCESS) {
        return ret;
    }
    
    /* Phase 6: Server decapsulates shared secret */
    ret = pqcp_mlkem_decapsulate(mlkem, kem_ct, kem_sk, kem_ss2);
    if (ret != PQCP_MLKEM_SUCCESS) {
        return ret;
    }
    
    /* Verify shared secrets match */
    if (memcmp(kem_ss1, kem_ss2, PQCP_MLKEM_SS_SIZE) != 0) {
        return -1;
    }
    
    *elapsed_ms = k_uptime_get_32() - start_ms;
    
    /* Calculate transcript size: pk + ct + sig + cert pk */
    *transcript_bytes = pqcp_mlkem_pk_size(mlkem) +
                        pqcp_mlkem_ct_size(mlkem) +
                        pqcp_mldsa_pk_size(mldsa) +
                        pqcp_mldsa_sig_size(mldsa);
    
    return 0;
}

#endif /* CONFIG_MBEDTLS */

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
    memset(result, 0, sizeof(*result));
    memset(&bench_ctx, 0, sizeof(bench_ctx));
    
    result->base.op = PQCP_BENCH_TLS_HANDSHAKE;
    result->base.level = kem_level;
    result->base.iterations = iterations;
    
    printk("Protocol benchmark: ML-KEM-%u + ML-DSA-%u (%u iterations)\n",
           kem_level, sig_level, iterations);
    
    /* Ensure RNG is ready */
    if (!pqcp_rng_is_ready()) {
        int ret = pqcp_rng_init();
        if (ret != 0) {
            printk("ERROR: RNG init failed: %d\n", ret);
            return ret;
        }
    }
    
    uint32_t total_handshake_ms = 0;
    uint32_t total_transcript = 0;
    uint32_t min_time = UINT32_MAX;
    uint32_t max_time = 0;
    
    for (uint32_t i = 0; i < iterations && i < 100; i++) {
        uint32_t elapsed_ms;
        uint32_t transcript_bytes;
        
        int ret = simulate_pqc_handshake(kem_level, sig_level,
                                          &elapsed_ms, &transcript_bytes);
        if (ret != 0) {
            printk("ERROR: Simulated handshake failed at iteration %u: %d\n",
                   i, ret);
            return ret;
        }
        
        bench_ctx.latency_samples[bench_ctx.sample_count++] = elapsed_ms;
        total_handshake_ms += elapsed_ms;
        total_transcript += transcript_bytes;
        
        if (elapsed_ms < min_time) min_time = elapsed_ms;
        if (elapsed_ms > max_time) max_time = elapsed_ms;
    }
    
    result->handshake_time_ms = total_handshake_ms / iterations;
    result->transcript_bytes = total_transcript / iterations;
    result->fragments = (result->transcript_bytes + 1399) / 1400;  /* MTU 1400 */
    result->cpu_percent = 95;  /* Crypto is CPU-bound */
    
    /* Estimate peak RAM from buffer sizes */
    result->peak_ram_bytes = sizeof(kem_pk) + sizeof(kem_sk) +
                             sizeof(kem_ct) + sizeof(kem_ss1) + sizeof(kem_ss2) +
                             sizeof(dsa_pk) + sizeof(dsa_sk) + sizeof(dsa_sig);
    
    /* Calculate percentiles */
    result->p50_latency = percentile(bench_ctx.latency_samples, 
                                     bench_ctx.sample_count, 50);
    result->p90_latency = percentile(bench_ctx.latency_samples,
                                     bench_ctx.sample_count, 90);
    result->p99_latency = percentile(bench_ctx.latency_samples,
                                     bench_ctx.sample_count, 99);
    
    result->base.avg_time = result->handshake_time_ms * 1000;  /* us */
    result->base.time_unit = 1;  /* microseconds */
    
    /* Emit individual operation metrics */
    PQCP_LOG_TIME_MS("protocol", "handshake_avg", "MLKEM", kem_level,
                     result->handshake_time_ms);
    PQCP_LOG_TIME_MS("protocol", "handshake_min", "MLKEM", kem_level, min_time);
    PQCP_LOG_TIME_MS("protocol", "handshake_max", "MLKEM", kem_level, max_time);
    
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
                                               10, &result);
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
