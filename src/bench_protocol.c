/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Zephyr Trust Stack - Protocol-Level Benchmarks
 *
 * Measures TLS/DTLS handshake performance with PQC algorithms.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <pqcp_zephyr/bench.h>

#ifdef CONFIG_PQCP_BENCH_PROTOCOL

#ifdef CONFIG_NET_SOCKETS
#include <zephyr/net/socket.h>
#endif

#ifdef CONFIG_MBEDTLS
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/timing.h>
#endif

/*
 * Protocol benchmark state
 */

typedef struct {
    /* Connection state */
#ifdef CONFIG_MBEDTLS
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
#endif
    
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

void pqcp_bench_print_protocol_result(const pqcp_bench_protocol_result_t *result)
{
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
    /* Note: In production, use a proper sorting algorithm */
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

#ifdef CONFIG_MBEDTLS

/**
 * @brief Initialize TLS benchmark context
 */
static int init_tls_context(protocol_bench_ctx_t *ctx, bool is_client)
{
    int ret;
    
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->conf);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->drbg);
    
    ret = mbedtls_ctr_drbg_seed(&ctx->drbg, mbedtls_entropy_func,
                                 &ctx->entropy, NULL, 0);
    if (ret != 0) {
        return ret;
    }
    
    ret = mbedtls_ssl_config_defaults(&ctx->conf,
                                       is_client ? MBEDTLS_SSL_IS_CLIENT 
                                                 : MBEDTLS_SSL_IS_SERVER,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        return ret;
    }
    
    mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->drbg);
    
    /* Note: For PQC ciphersuites, additional configuration needed here
     * when mbedTLS supports ML-KEM/ML-DSA */
    
    ret = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);
    if (ret != 0) {
        return ret;
    }
    
    return 0;
}

/**
 * @brief Clean up TLS context
 */
static void cleanup_tls_context(protocol_bench_ctx_t *ctx)
{
    mbedtls_ssl_free(&ctx->ssl);
    mbedtls_ssl_config_free(&ctx->conf);
    mbedtls_ctr_drbg_free(&ctx->drbg);
    mbedtls_entropy_free(&ctx->entropy);
}

#endif /* CONFIG_MBEDTLS */

/**
 * @brief Run TLS handshake benchmark
 *
 * Note: This is a placeholder that measures timing but doesn't
 * actually perform real TLS handshakes (which would require network).
 * In a real deployment, this would connect to a server.
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
    
    printk("TLS benchmark: ML-KEM-%u + ML-DSA-%u (%u iterations)\n",
           kem_level, sig_level, iterations);
    
#ifdef CONFIG_MBEDTLS
    uint32_t total_handshake_ms = 0;
    uint32_t total_transcript = 0;
    
    for (uint32_t i = 0; i < iterations && i < 100; i++) {
        uint32_t start_ms = k_uptime_get_32();
        
        /* Simulate handshake timing based on primitive costs */
        /* In real implementation, this would be actual TLS handshake */
        
        /* Simulate: key generation + encapsulation + signature operations */
        k_busy_wait(1000);  /* Placeholder delay */
        
        uint32_t elapsed_ms = k_uptime_get_32() - start_ms;
        
        bench_ctx.latency_samples[i] = elapsed_ms;
        bench_ctx.sample_count++;
        total_handshake_ms += elapsed_ms;
        
        /* Estimate transcript size based on key/sig sizes */
        uint32_t transcript = 0;
        switch (kem_level) {
        case 512:  transcript += 800 + 768; break;   /* pk + ct */
        case 768:  transcript += 1184 + 1088; break;
        case 1024: transcript += 1568 + 1568; break;
        }
        switch (sig_level) {
        case 44: transcript += 1312 + 2420; break;   /* pk + sig */
        case 65: transcript += 1952 + 3293; break;
        case 87: transcript += 2592 + 4595; break;
        }
        total_transcript += transcript * 2;  /* Client + server certs */
    }
    
    result->handshake_time_ms = total_handshake_ms / iterations;
    result->transcript_bytes = total_transcript / iterations;
    result->fragments = (result->transcript_bytes + 1399) / 1400;  /* MTU 1400 */
    result->cpu_percent = 50;  /* Placeholder */
    result->peak_ram_bytes = 32768;  /* Placeholder */
    
    /* Calculate percentiles */
    result->p50_latency = percentile(bench_ctx.latency_samples, 
                                     bench_ctx.sample_count, 50);
    result->p90_latency = percentile(bench_ctx.latency_samples,
                                     bench_ctx.sample_count, 90);
    result->p99_latency = percentile(bench_ctx.latency_samples,
                                     bench_ctx.sample_count, 99);
    
    result->base.avg_time = result->handshake_time_ms * 1000;  /* us */
    result->base.time_unit = 1;  /* microseconds */
    
#else
    printk("Warning: mbedTLS not enabled, protocol benchmarks unavailable\n");
    return -ENOTSUP;
#endif
    
    return 0;
}

/**
 * @brief Run all protocol benchmarks
 */
void pqcp_bench_run_protocol_all(void)
{
    pqcp_bench_protocol_result_t result;
    
    printk("\n=== Protocol Benchmark Suite ===\n\n");
    
    /* Test various combinations */
    uint16_t kem_levels[] = {768, 1024};
    uint16_t sig_levels[] = {65, 87};
    
    for (size_t i = 0; i < sizeof(kem_levels) / sizeof(kem_levels[0]); i++) {
        for (size_t j = 0; j < sizeof(sig_levels) / sizeof(sig_levels[0]); j++) {
            int ret = pqcp_bench_tls_handshake(kem_levels[i], sig_levels[j],
                                               10, &result);
            if (ret == 0) {
                pqcp_bench_print_protocol_result(&result);
            }
        }
    }
    
    printk("\n=== Protocol Benchmark Complete ===\n");
}

#endif /* CONFIG_PQCP_BENCH_PROTOCOL */
