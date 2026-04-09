/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP TLS self-test helper tests
 */

#include <zephyr/ztest.h>
#include <zephyr/sys/util.h>
#include <zephyr/sys/printk-hooks.h>

#include <pqcp_zephyr/tls_selftest.h>

#include <string.h>

static char printk_capture[8192];
static size_t printk_capture_len;

static int capture_printk(int c)
{
    if (printk_capture_len < sizeof(printk_capture) - 1U) {
        printk_capture[printk_capture_len++] = (char)c;
        printk_capture[printk_capture_len] = '\0';
    }

    return c;
}

static void reset_capture(void)
{
    memset(printk_capture, 0, sizeof(printk_capture));
    printk_capture_len = 0U;
}

/*
 * Stress-oriented TLS coverage is compiled only when overlay-fuzz.conf
 * enables CONFIG_PQCP_FUZZ_TESTS for this test image.
 */
#if defined(CONFIG_PQCP_FUZZ_TESTS)
static const uint16_t enabled_kem_levels[] = {
#if defined(CONFIG_PQCP_MLKEM_LEVEL_512)
    512,
#endif
#if defined(CONFIG_PQCP_MLKEM_LEVEL_768)
    768,
#endif
#if defined(CONFIG_PQCP_MLKEM_LEVEL_1024)
    1024,
#endif
};

static const uint16_t enabled_sig_levels[] = {
#if defined(CONFIG_PQCP_MLDSA_LEVEL_44)
    44,
#endif
#if defined(CONFIG_PQCP_MLDSA_LEVEL_65)
    65,
#endif
#if defined(CONFIG_PQCP_MLDSA_LEVEL_87)
    87,
#endif
};

static uint32_t fuzz_state = 0x51d2e34aU;

static uint32_t fuzz_next(void)
{
    fuzz_state = (1664525U * fuzz_state) + 1013904223U;
    return fuzz_state;
}
#endif

ZTEST(pqcp_tls_selftest, test_tls_selftest_report_success)
{
    pqcp_tls_selftest_config_t cfg = {
        .kem_level = 768,
        .sig_level = 65,
        .initialize_rng = true,
        .initialize_psa = false,
        .emit_metrics = false,
    };
    pqcp_tls_selftest_report_t report;

    zassert_equal(pqcp_tls_selftest_run(&cfg, &report), 0);
    zassert_true(report.handshake_us > 0U, "handshake should be timed");
    zassert_true(report.auth_us > 0U, "auth stage should be timed");
    zassert_true(report.key_exchange_us > 0U, "key exchange should be timed");
    zassert_true(report.client_bytes > 0U, "client payload should be present");
    zassert_true(report.server_bytes > 0U, "server payload should be present");
    zassert_equal(report.transcript_bytes,
                  report.client_bytes + report.server_bytes);
    zassert_true(report.packets > 0U, "packet estimate should be present");
    zassert_true(report.working_set_bytes > 0U, "working set should be tracked");
}

ZTEST(pqcp_tls_selftest, test_tls_selftest_emits_metrics)
{
    pqcp_tls_selftest_config_t cfg = {
        .kem_level = 768,
        .sig_level = 65,
        .initialize_rng = true,
        .initialize_psa = true,
        .emit_metrics = true,
    };
    pqcp_tls_selftest_report_t report;
    printk_hook_fn_t previous_hook;

    reset_capture();
    previous_hook = __printk_get_hook();
    __printk_hook_install(capture_printk);

    zassert_equal(pqcp_tls_selftest_run(&cfg, &report), 0);

    __printk_hook_install(previous_hook);

    zassert_true(report.psa_ready, "PSA should be initialized in self-test");
    zassert_not_null(strstr(printk_capture,
                            "PQCP_METRIC,driver,keygen,MLKEM,768,time,"));
    zassert_not_null(strstr(printk_capture,
                            "PQCP_METRIC,protocol,handshake,TLS13,0,time,"));
    zassert_not_null(strstr(printk_capture,
                            "PQCP_METRIC,protocol,handshake,TLS13,0,transcript_bytes,"));
}

#if defined(CONFIG_PQCP_FUZZ_TESTS)
ZTEST(pqcp_tls_selftest, test_tls_selftest_stress_repeated_runs)
{
    pqcp_tls_selftest_report_t report;

    zassert_true(ARRAY_SIZE(enabled_kem_levels) > 0U,
                 "at least one ML-KEM level must be enabled");
    zassert_true(ARRAY_SIZE(enabled_sig_levels) > 0U,
                 "at least one ML-DSA level must be enabled");

    for (size_t i = 0U; i < 16U; ++i) {
        pqcp_tls_selftest_config_t cfg = {
            .kem_level = enabled_kem_levels[fuzz_next() % ARRAY_SIZE(enabled_kem_levels)],
            .sig_level = enabled_sig_levels[fuzz_next() % ARRAY_SIZE(enabled_sig_levels)],
            .initialize_rng = true,
            .initialize_psa = ((fuzz_next() & 0x1U) != 0U),
            .emit_metrics = ((fuzz_next() & 0x1U) != 0U),
        };

        reset_capture();
        zassert_equal(pqcp_tls_selftest_run(&cfg, &report), 0);
        zassert_equal(report.kem_level, cfg.kem_level);
        zassert_equal(report.sig_level, cfg.sig_level);
        zassert_true(report.handshake_us > 0U, "handshake should be timed");
        zassert_true(report.auth_us > 0U, "auth stage should be timed");
        zassert_true(report.key_exchange_us > 0U,
                     "key exchange stage should be timed");
        zassert_true(report.transcript_bytes > 0U,
                     "transcript bytes should be tracked");
        zassert_true(report.packets > 0U, "packet estimate should be tracked");
    }
}
#endif

static void *pqcp_tls_selftest_setup(void)
{
    return NULL;
}

ZTEST_SUITE(pqcp_tls_selftest, NULL, pqcp_tls_selftest_setup, NULL, NULL, NULL);
