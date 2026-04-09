/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP TLS self-test helper tests
 */

#include <zephyr/ztest.h>
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

static void *pqcp_tls_selftest_setup(void)
{
    return NULL;
}

ZTEST_SUITE(pqcp_tls_selftest, NULL, pqcp_tls_selftest_setup, NULL, NULL, NULL);
