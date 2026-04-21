/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Zephyr Trust Stack - Primitive-Level Benchmarks
 *
 * Measures performance of ML-KEM and ML-DSA operations.
 */
#include <pqcp_zephyr/rng.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <pqcp_zephyr/bench.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>

#include <string.h>

#ifdef CONFIG_PQCP_BENCH

/*
 * Timing infrastructure
 */

/*
 * Use Zephyr's public Arm Cortex-M DWT helpers when the helper header is
 * exported by the current tree. This mirrors Zephyr's own Arm timing code
 * include style (`<cortex_m/dwt.h>`) instead of depending on private paths.
 */
#if defined(CONFIG_CPU_CORTEX_M_HAS_DWT) && defined(CONFIG_PQCP_BENCH_CYCLE_COUNTER)
#if defined(__has_include) && !defined(__CPPCHECK__)
#if __has_include(<cortex_m/dwt.h>)
#include <cortex_m/dwt.h>
#define USE_DWT_CYCLES 1
#endif
#endif
#endif

#ifndef USE_DWT_CYCLES
#define USE_DWT_CYCLES 0
#endif

static bool bench_initialized = false;

static const char *pqcp_bench_metric_component(pqcp_bench_op_t op)
{
    if (op >= PQCP_BENCH_MLKEM_KEYPAIR && op <= PQCP_BENCH_MLKEM_DECAPS) {
        return "MLKEM";
    }
    if (op >= PQCP_BENCH_MLDSA_KEYPAIR && op <= PQCP_BENCH_MLDSA_VERIFY) {
        return "MLDSA";
    }
    return "RNG";
}

static const char *pqcp_bench_metric_operation(pqcp_bench_op_t op)
{
    switch (op) {
    case PQCP_BENCH_MLKEM_KEYPAIR:
    case PQCP_BENCH_MLDSA_KEYPAIR:
        return "keygen";
    case PQCP_BENCH_MLKEM_ENCAPS:
        return "encaps";
    case PQCP_BENCH_MLKEM_DECAPS:
        return "decaps";
    case PQCP_BENCH_MLDSA_SIGN:
        return "sign";
    case PQCP_BENCH_MLDSA_VERIFY:
        return "verify";
    case PQCP_BENCH_RNG_ENTROPY:
        return "entropy";
    default:
        return "unknown";
    }
}

int pqcp_bench_init(void)
{
    if (bench_initialized) {
        return 0;
    }
    
#if USE_DWT_CYCLES
    z_arm_dwt_init();
    z_arm_dwt_init_cycle_counter();
#endif
    
    bench_initialized = true;
    return 0;
}

uint64_t pqcp_bench_start_timing(void)
{
#if USE_DWT_CYCLES
    return z_arm_dwt_get_cycles();
#else
    return k_cycle_get_32();
#endif
}

uint64_t pqcp_bench_end_timing(uint64_t start)
{
#if USE_DWT_CYCLES
    uint32_t end = z_arm_dwt_get_cycles();
    return (uint64_t)(end - (uint32_t)start);
#else
    uint32_t end = k_cycle_get_32();
    return (uint64_t)(end - (uint32_t)start);
#endif
}

uint64_t pqcp_bench_cycles_to_us(uint64_t cycles)
{
    return (cycles * 1000000ULL) / CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC;
}

uint32_t pqcp_bench_get_stack_usage(void)
{
#if defined(CONFIG_THREAD_STACK_INFO) && defined(CONFIG_INIT_STACKS)
    struct k_thread *thread = k_current_get();
    size_t unused = 0;
    
    int ret = k_thread_stack_space_get(thread, &unused);
    if (ret == 0) {
        /* Return used = total - unused */
        return (uint32_t)(thread->stack_info.size - unused);
    }
#endif
    return 0;
}

const char *pqcp_bench_op_name(pqcp_bench_op_t op)
{
    switch (op) {
    case PQCP_BENCH_MLKEM_KEYPAIR: return "MLKEM_KEYPAIR";
    case PQCP_BENCH_MLKEM_ENCAPS:  return "MLKEM_ENCAPS";
    case PQCP_BENCH_MLKEM_DECAPS:  return "MLKEM_DECAPS";
    case PQCP_BENCH_MLDSA_KEYPAIR: return "MLDSA_KEYPAIR";
    case PQCP_BENCH_MLDSA_SIGN:    return "MLDSA_SIGN";
    case PQCP_BENCH_MLDSA_VERIFY:  return "MLDSA_VERIFY";
    case PQCP_BENCH_RNG_ENTROPY:   return "RNG_ENTROPY";
    default: return "UNKNOWN";
    }
}

void pqcp_bench_print_result(const pqcp_bench_result_t *result)
{
    const char *unit = (result->time_unit == 0) ? "cycles" : "us";
    const char *backend = (result->backend == 0) ? "C" : "native";
    const char *algorithm = pqcp_bench_metric_component(result->op);
    const char *operation = pqcp_bench_metric_operation(result->op);
    
    printk("PRIM,%s%u,%s,%s=%llu,us=%llu,stack=%u,text=%u,bss=%u,backend=%s\n",
           algorithm,
           result->level,
           pqcp_bench_op_name(result->op),
           unit,
           result->avg_time,
           result->avg_us,
           result->stack_used,
           result->text_size,
           result->bss_size,
           backend);

    if (result->avg_cycles > 0U) {
        PQCP_LOG_CYCLES("primitive", operation, algorithm, result->level,
                        result->avg_cycles);
    }
    if (result->avg_us > 0U) {
        PQCP_LOG_TIME_US("primitive", operation, algorithm, result->level,
                         result->avg_us);
    }
    if (result->stack_used > 0U) {
        PQCP_LOG_STACK("primitive", "total", algorithm, result->level,
                       result->stack_used);
    }
}

/*
 * ML-KEM Benchmarks
 */

int pqcp_bench_mlkem(uint16_t level,
                     const pqcp_bench_config_t *config,
                     pqcp_bench_result_t results[3])
{
    pqcp_bench_config_t cfg;
    
    if (config == NULL) {
        cfg = (pqcp_bench_config_t)PQCP_BENCH_CONFIG_DEFAULT;
    } else {
        cfg = *config;
    }
    
    pqcp_mlkem_level_t mlkem_level;
    switch (level) {
    case 512:  mlkem_level = PQCP_MLKEM_512;  break;
    case 768:  mlkem_level = PQCP_MLKEM_768;  break;
    case 1024: mlkem_level = PQCP_MLKEM_1024; break;
    default: return -1;
    }
    
    /* Allocate buffers */
    static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    static uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
    static uint8_t ss1[PQCP_MLKEM_SS_SIZE];
    static uint8_t ss2[PQCP_MLKEM_SS_SIZE];
    
    uint64_t cycles_totals[3] = {0, 0, 0};
    uint64_t min_cycles[3] = {UINT64_MAX, UINT64_MAX, UINT64_MAX};
    uint64_t max_cycles[3] = {0, 0, 0};
    
    /* Initialize benchmark infrastructure */
    pqcp_bench_init();
    
    if (cfg.verbose) {
        printk("Benchmarking ML-KEM-%u (%u iterations, %u warmup)\n",
               level, cfg.iterations, cfg.warmup);
    }
    
    /* Warmup */
    for (uint32_t i = 0; i < cfg.warmup; i++) {
        pqcp_mlkem_keypair(mlkem_level, pk, sk);
        pqcp_mlkem_encapsulate(mlkem_level, pk, ct, ss1);
        pqcp_mlkem_decapsulate(mlkem_level, ct, sk, ss2);
    }
    
    /* Benchmark keygen */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mlkem_keypair(mlkem_level, pk, sk);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[0] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[0]) min_cycles[0] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[0]) max_cycles[0] = elapsed_cycles;
    }
    
    /* Benchmark encapsulation */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mlkem_encapsulate(mlkem_level, pk, ct, ss1);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[1] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[1]) min_cycles[1] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[1]) max_cycles[1] = elapsed_cycles;
    }
    
    /* Benchmark decapsulation */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mlkem_decapsulate(mlkem_level, ct, sk, ss2);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[2] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[2]) min_cycles[2] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[2]) max_cycles[2] = elapsed_cycles;
    }
    
    /* Fill results */
    static const pqcp_bench_op_t ops[3] = {
        PQCP_BENCH_MLKEM_KEYPAIR,
        PQCP_BENCH_MLKEM_ENCAPS,
        PQCP_BENCH_MLKEM_DECAPS
    };
    
    for (int i = 0; i < 3; i++) {
        uint64_t avg_cycles = cycles_totals[i] / cfg.iterations;
        uint64_t avg_us = pqcp_bench_cycles_to_us(avg_cycles);

        results[i].op = ops[i];
        results[i].level = level;
        results[i].iterations = cfg.iterations;
        results[i].total_time = cfg.use_cycles ? cycles_totals[i]
                                               : pqcp_bench_cycles_to_us(cycles_totals[i]);
        results[i].min_time = cfg.use_cycles ? min_cycles[i]
                                             : pqcp_bench_cycles_to_us(min_cycles[i]);
        results[i].max_time = cfg.use_cycles ? max_cycles[i]
                                             : pqcp_bench_cycles_to_us(max_cycles[i]);
        results[i].avg_time = cfg.use_cycles ? avg_cycles : avg_us;
        results[i].avg_cycles = avg_cycles;
        results[i].avg_us = avg_us;
        results[i].stack_used = 0;
        if (cfg.measure_stack) {
            results[i].stack_used = pqcp_bench_get_stack_usage();
        }
        results[i].heap_used = 0;
        results[i].text_size = 0;  /* Filled by scripts */
        results[i].data_size = 0;
        results[i].bss_size = 0;
        results[i].time_unit = cfg.use_cycles ? 0 : 1;
#ifdef CONFIG_PQCP_BACKEND_FORCE_NATIVE
        results[i].backend = 1;
#else
        results[i].backend = 0;
#endif
    }
    
    return 0;
}

/*
 * ML-DSA Benchmarks
 */

int pqcp_bench_mldsa(uint16_t level,
                     size_t msg_len,
                     const pqcp_bench_config_t *config,
                     pqcp_bench_result_t results[3])
{
    pqcp_bench_config_t cfg;
    
    if (config == NULL) {
        cfg = (pqcp_bench_config_t)PQCP_BENCH_CONFIG_DEFAULT;
    } else {
        cfg = *config;
    }
    
    pqcp_mldsa_level_t mldsa_level;
    switch (level) {
    case 44: mldsa_level = PQCP_MLDSA_44; break;
    case 65: mldsa_level = PQCP_MLDSA_65; break;
    case 87: mldsa_level = PQCP_MLDSA_87; break;
    default: return -1;
    }
    
    /* Allocate buffers */
    static uint8_t pk[PQCP_MLDSA_PK_SIZE_MAX];
    static uint8_t sk[PQCP_MLDSA_SK_SIZE_MAX];
    static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
    static uint8_t msg[256];  /* Max message size for benchmark */
    
    if (msg_len > sizeof(msg)) {
        msg_len = sizeof(msg);
    }
    
    /* Initialize message with pattern */
    for (size_t i = 0; i < msg_len; i++) {
        msg[i] = (uint8_t)(i & 0xFF);
    }
    
    uint64_t cycles_totals[3] = {0, 0, 0};
    uint64_t min_cycles[3] = {UINT64_MAX, UINT64_MAX, UINT64_MAX};
    uint64_t max_cycles[3] = {0, 0, 0};
    
    pqcp_bench_init();
    
    if (cfg.verbose) {
        printk("Benchmarking ML-DSA-%u (%u iterations, msg_len=%zu)\n",
               level, cfg.iterations, msg_len);
    }
    
    /* Warmup */
    for (uint32_t i = 0; i < cfg.warmup; i++) {
        pqcp_mldsa_keypair(mldsa_level, pk, sk);
        pqcp_mldsa_sign(mldsa_level, sk, msg, msg_len, NULL, 0, sig);
        pqcp_mldsa_verify(mldsa_level, pk, msg, msg_len, NULL, 0, sig);
    }
    
    /* Generate key for sign/verify benchmarks */
    pqcp_mldsa_keypair(mldsa_level, pk, sk);
    
    /* Benchmark keygen */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mldsa_keypair(mldsa_level, pk, sk);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[0] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[0]) min_cycles[0] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[0]) max_cycles[0] = elapsed_cycles;
    }
    
    /* Benchmark signing */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mldsa_sign(mldsa_level, sk, msg, msg_len, NULL, 0, sig);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[1] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[1]) min_cycles[1] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[1]) max_cycles[1] = elapsed_cycles;
    }
    
    /* Benchmark verification */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_mldsa_verify(mldsa_level, pk, msg, msg_len, NULL, 0, sig);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        cycles_totals[2] += elapsed_cycles;
        if (elapsed_cycles < min_cycles[2]) min_cycles[2] = elapsed_cycles;
        if (elapsed_cycles > max_cycles[2]) max_cycles[2] = elapsed_cycles;
    }
    
    /* Fill results */
    static const pqcp_bench_op_t ops[3] = {
        PQCP_BENCH_MLDSA_KEYPAIR,
        PQCP_BENCH_MLDSA_SIGN,
        PQCP_BENCH_MLDSA_VERIFY
    };
    
    for (int i = 0; i < 3; i++) {
        uint64_t avg_cycles = cycles_totals[i] / cfg.iterations;
        uint64_t avg_us = pqcp_bench_cycles_to_us(avg_cycles);

        results[i].op = ops[i];
        results[i].level = level;
        results[i].iterations = cfg.iterations;
        results[i].total_time = cfg.use_cycles ? cycles_totals[i]
                                               : pqcp_bench_cycles_to_us(cycles_totals[i]);
        results[i].min_time = cfg.use_cycles ? min_cycles[i]
                                             : pqcp_bench_cycles_to_us(min_cycles[i]);
        results[i].max_time = cfg.use_cycles ? max_cycles[i]
                                             : pqcp_bench_cycles_to_us(max_cycles[i]);
        results[i].avg_time = cfg.use_cycles ? avg_cycles : avg_us;
        results[i].avg_cycles = avg_cycles;
        results[i].avg_us = avg_us;
        results[i].stack_used = 0;
        if (cfg.measure_stack) {
            results[i].stack_used = pqcp_bench_get_stack_usage();
        }
        results[i].heap_used = 0;
        results[i].text_size = 0;
        results[i].data_size = 0;
        results[i].bss_size = 0;
        results[i].time_unit = cfg.use_cycles ? 0 : 1;
#ifdef CONFIG_PQCP_BACKEND_FORCE_NATIVE
        results[i].backend = 1;
#else
        results[i].backend = 0;
#endif
    }
    
    return 0;
}

/*
 * RNG Benchmarks
 */

int pqcp_bench_rng(size_t block_size,
                   const pqcp_bench_config_t *config,
                   pqcp_bench_result_t *result)
{
    pqcp_bench_config_t cfg;
    
    if (config == NULL) {
        cfg = (pqcp_bench_config_t)PQCP_BENCH_CONFIG_DEFAULT;
    } else {
        cfg = *config;
    }
    
    static uint8_t buffer[256];
    if (block_size > sizeof(buffer)) {
        block_size = sizeof(buffer);
    }
    
    pqcp_bench_init();
    
    uint64_t total_cycles = 0;
    uint64_t min_cycles = UINT64_MAX;
    uint64_t max_cycles = 0;
    
    /* Warmup */
    for (uint32_t i = 0; i < cfg.warmup; i++) {
        pqcp_rng_get_bytes(buffer, block_size);
    }
    
    /* Benchmark */
    for (uint32_t i = 0; i < cfg.iterations; i++) {
        uint64_t start = pqcp_bench_start_timing();
        pqcp_rng_get_bytes(buffer, block_size);
        uint64_t elapsed_cycles = pqcp_bench_end_timing(start);

        total_cycles += elapsed_cycles;
        if (elapsed_cycles < min_cycles) min_cycles = elapsed_cycles;
        if (elapsed_cycles > max_cycles) max_cycles = elapsed_cycles;
    }
    
    result->avg_cycles = total_cycles / cfg.iterations;
    result->avg_us = pqcp_bench_cycles_to_us(result->avg_cycles);
    result->op = PQCP_BENCH_RNG_ENTROPY;
    result->level = (uint16_t)block_size;
    result->iterations = cfg.iterations;
    result->total_time = cfg.use_cycles ? total_cycles
                                        : pqcp_bench_cycles_to_us(total_cycles);
    result->min_time = cfg.use_cycles ? min_cycles
                                      : pqcp_bench_cycles_to_us(min_cycles);
    result->max_time = cfg.use_cycles ? max_cycles
                                      : pqcp_bench_cycles_to_us(max_cycles);
    result->avg_time = cfg.use_cycles ? result->avg_cycles : result->avg_us;
    result->stack_used = 0;
    result->heap_used = 0;
    result->text_size = 0;
    result->data_size = 0;
    result->bss_size = 0;
    result->time_unit = cfg.use_cycles ? 0 : 1;
    result->backend = 0;
    
    return 0;
}

/*
 * Run all benchmarks
 */

void pqcp_bench_run_all(const pqcp_bench_config_t *config)
{
    pqcp_bench_result_t results[3];
    
    printk("\n=== PQCP Benchmark Suite ===\n\n");
    
#ifdef CONFIG_PQCP_MLKEM_LEVEL_512
    printk("--- ML-KEM-512 ---\n");
    pqcp_bench_mlkem(512, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif
    
#ifdef CONFIG_PQCP_MLKEM_LEVEL_768
    printk("\n--- ML-KEM-768 ---\n");
    pqcp_bench_mlkem(768, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif
    
#ifdef CONFIG_PQCP_MLKEM_LEVEL_1024
    printk("\n--- ML-KEM-1024 ---\n");
    pqcp_bench_mlkem(1024, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif
    
#ifdef CONFIG_PQCP_MLDSA_LEVEL_44
    printk("\n--- ML-DSA-44 ---\n");
    pqcp_bench_mldsa(44, 64, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif
    
#ifdef CONFIG_PQCP_MLDSA_LEVEL_65
    printk("\n--- ML-DSA-65 ---\n");
    pqcp_bench_mldsa(65, 64, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif
    
#ifdef CONFIG_PQCP_MLDSA_LEVEL_87
    printk("\n--- ML-DSA-87 ---\n");
    pqcp_bench_mldsa(87, 64, config, results);
    for (int i = 0; i < 3; i++) {
        pqcp_bench_print_result(&results[i]);
    }
#endif
    
    printk("\n--- RNG ---\n");
    pqcp_bench_result_t rng_result;
    pqcp_bench_rng(32, config, &rng_result);
    pqcp_bench_print_result(&rng_result);
    
    printk("\n=== Benchmark Complete ===\n");
}

#endif /* CONFIG_PQCP_BENCH */
