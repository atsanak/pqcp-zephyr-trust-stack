/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Zephyr Trust Stack - Benchmarking API
 *
 * This header provides the benchmarking harness for measuring performance
 * of PQCP cryptographic operations and protocols.
 */

#ifndef PQCP_ZEPHYR_BENCH_H
#define PQCP_ZEPHYR_BENCH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Benchmark Types
 */

/* Benchmark operation IDs */
typedef enum {
    /* ML-KEM operations */
    PQCP_BENCH_MLKEM_KEYPAIR     = 0x0100,
    PQCP_BENCH_MLKEM_ENCAPS      = 0x0101,
    PQCP_BENCH_MLKEM_DECAPS      = 0x0102,
    
    /* ML-DSA operations */
    PQCP_BENCH_MLDSA_KEYPAIR     = 0x0200,
    PQCP_BENCH_MLDSA_SIGN        = 0x0201,
    PQCP_BENCH_MLDSA_VERIFY      = 0x0202,
    PQCP_BENCH_MLDSA_SIGN_STREAM = 0x0203,
    
    /* Protocol operations */
    PQCP_BENCH_TLS_HANDSHAKE     = 0x0300,
    PQCP_BENCH_DTLS_HANDSHAKE    = 0x0301,
    
    /* RNG operations */
    PQCP_BENCH_RNG_ENTROPY       = 0x0400,
    PQCP_BENCH_RNG_DRBG          = 0x0401,
} pqcp_bench_op_t;

/* Benchmark result structure */
typedef struct pqcp_bench_result {
    /* Operation identifier */
    pqcp_bench_op_t op;
    
    /* Security level (e.g., 512, 768, 1024 for ML-KEM) */
    uint16_t level;
    
    /* Number of iterations performed */
    uint32_t iterations;
    
    /* Timing measurements (in cycles or microseconds) */
    uint64_t total_time;
    uint64_t min_time;
    uint64_t max_time;
    uint64_t avg_time;  /* total_time / iterations */
    
    /* Memory measurements */
    uint32_t stack_used;     /* Peak stack usage in bytes */
    uint32_t heap_used;      /* Peak heap usage in bytes (if applicable) */
    
    /* Code size (from build artifacts, filled in by scripts) */
    uint32_t text_size;      /* .text section size */
    uint32_t data_size;      /* .data section size */
    uint32_t bss_size;       /* .bss section size */
    
    /* Flags */
    uint8_t  time_unit;      /* 0 = cycles, 1 = microseconds */
    uint8_t  backend;        /* 0 = C, 1 = native assembly */
} pqcp_bench_result_t;

/* Protocol benchmark result (extended) */
typedef struct pqcp_bench_protocol_result {
    /* Base result */
    pqcp_bench_result_t base;
    
    /* Protocol-specific metrics */
    uint32_t handshake_time_ms;   /* Handshake latency */
    uint32_t transcript_bytes;    /* Total bytes exchanged */
    uint16_t fragments;           /* Number of network fragments */
    uint8_t  cpu_percent;         /* CPU utilization during handshake */
    uint32_t peak_ram_bytes;      /* Peak RAM usage */
    
    /* Percentiles (in ms) */
    uint32_t p50_latency;
    uint32_t p90_latency;
    uint32_t p99_latency;
} pqcp_bench_protocol_result_t;

/*
 * Benchmark Configuration
 */

typedef struct pqcp_bench_config {
    uint32_t iterations;     /* Number of iterations */
    uint32_t warmup;         /* Warmup iterations */
    uint8_t  use_cycles;     /* Use cycle counter (vs time) */
    uint8_t  measure_stack;  /* Measure stack usage */
    uint8_t  verbose;        /* Print progress */
} pqcp_bench_config_t;

/* Default configuration */
#define PQCP_BENCH_CONFIG_DEFAULT { \
    .iterations = 100, \
    .warmup = 10, \
    .use_cycles = 1, \
    .measure_stack = 1, \
    .verbose = 0 \
}

/*
 * Benchmark Functions
 */

/**
 * @brief Initialize the benchmark harness.
 *
 * Sets up timing infrastructure (cycle counter or timer).
 *
 * @return 0 on success, negative error code on failure.
 */
int pqcp_bench_init(void);

/**
 * @brief Run ML-KEM benchmarks.
 *
 * @param level   Security level (512, 768, or 1024).
 * @param config  Benchmark configuration (NULL for defaults).
 * @param results Array of 3 results (keypair, encaps, decaps).
 *
 * @return 0 on success, negative error code on failure.
 */
int pqcp_bench_mlkem(uint16_t level,
                     const pqcp_bench_config_t *config,
                     pqcp_bench_result_t results[3]);

/**
 * @brief Run ML-DSA benchmarks.
 *
 * @param level   Security level (44, 65, or 87).
 * @param msg_len Message length for sign/verify.
 * @param config  Benchmark configuration (NULL for defaults).
 * @param results Array of 3 results (keypair, sign, verify).
 *
 * @return 0 on success, negative error code on failure.
 */
int pqcp_bench_mldsa(uint16_t level,
                     size_t msg_len,
                     const pqcp_bench_config_t *config,
                     pqcp_bench_result_t results[3]);

/**
 * @brief Run RNG benchmarks.
 *
 * @param block_size Size of random blocks to generate.
 * @param config     Benchmark configuration.
 * @param result     Output result.
 *
 * @return 0 on success, negative error code on failure.
 */
int pqcp_bench_rng(size_t block_size,
                   const pqcp_bench_config_t *config,
                   pqcp_bench_result_t *result);

/**
 * @brief Run all primitive benchmarks and print results.
 *
 * This is a convenience function that runs ML-KEM and ML-DSA
 * benchmarks for all enabled security levels and prints
 * the results in a parseable format.
 *
 * @param config  Benchmark configuration (NULL for defaults).
 */
void pqcp_bench_run_all(const pqcp_bench_config_t *config);

/**
 * @brief Print a benchmark result in log format.
 *
 * Outputs a line like:
 * PRIM,MLKEM768,KEYGEN,cycles=12345,stack=2048,text=4096,bss=256
 *
 * @param result The benchmark result to print.
 */
void pqcp_bench_print_result(const pqcp_bench_result_t *result);

/**
 * @brief Print a protocol benchmark result.
 *
 * Outputs a line like:
 * TLS,MLKEM768+MLDSA65,handshake_ms=150,cpu_pct=45,peak_kib=32,...
 *
 * @param result The protocol benchmark result to print.
 */
void pqcp_bench_print_protocol_result(const pqcp_bench_protocol_result_t *result);

/*
 * Low-level timing utilities
 */

/**
 * @brief Start timing measurement.
 *
 * @return Start timestamp (cycles or ticks).
 */
uint64_t pqcp_bench_start_timing(void);

/**
 * @brief End timing measurement.
 *
 * @param start Start timestamp from pqcp_bench_start_timing().
 * @return Elapsed time (cycles or microseconds based on config).
 */
uint64_t pqcp_bench_end_timing(uint64_t start);

/**
 * @brief Get stack high water mark.
 *
 * Uses Zephyr's stack sentinel/analysis features if available.
 *
 * @return Stack usage in bytes, or 0 if not measurable.
 */
uint32_t pqcp_bench_get_stack_usage(void);

/**
 * @brief Get operation name string.
 *
 * @param op Operation ID.
 * @return Human-readable name like "MLKEM_KEYPAIR".
 */
const char *pqcp_bench_op_name(pqcp_bench_op_t op);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_BENCH_H */
