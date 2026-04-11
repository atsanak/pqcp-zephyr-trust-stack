/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP ACVP command library tests
 */

#include <zephyr/ztest.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/acvp_cmd.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/mlkem.h>

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#define TEST_BUFFER_SIZE 16384

static uint8_t work_buffer[TEST_BUFFER_SIZE];
static uint8_t response_buffer[TEST_BUFFER_SIZE];
static char line_buffer[TEST_BUFFER_SIZE * 2];
static char hex_buffer[TEST_BUFFER_SIZE * 2];
static char response_line[TEST_BUFFER_SIZE * 2];

static int run_command(const char *fmt, struct pqcp_acvp_response *resp, ...)
{
    va_list args;
    int written;

    pqcp_acvp_response_init(resp, response_buffer, sizeof(response_buffer));

    va_start(args, resp);
    written = vsnprintk(line_buffer, sizeof(line_buffer), fmt, args);
    va_end(args);

    zassert_true(written >= 0 && written < (int)sizeof(line_buffer),
                 "command buffer overflow");

    return pqcp_acvp_process_command(line_buffer, work_buffer,
                                     sizeof(work_buffer), resp);
}

static void bytes_to_hex(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    zassert_true(out_size >= (len * 2U) + 1U, "hex buffer too small");
    pqcp_acvp_bytes_to_hex(data, len, out);
}

static void assert_response_line(const struct pqcp_acvp_response *resp,
                                 const char *expected)
{
    zassert_equal(pqcp_acvp_format_response_line(resp, response_line,
                                                 sizeof(response_line)),
                  0);
    zassert_equal(strcmp(response_line, expected), 0,
                  "unexpected response line: %s", response_line);
}

static void assert_response_prefix(const struct pqcp_acvp_response *resp,
                                   const char *expected_prefix)
{
    zassert_equal(pqcp_acvp_format_response_line(resp, response_line,
                                                 sizeof(response_line)),
                  0);
    zassert_not_null(strstr(response_line, expected_prefix),
                     "response line %s missing prefix %s",
                     response_line, expected_prefix);
}

ZTEST(pqcp_acvp_serial, test_mlkem_roundtrip_commands)
{
    struct pqcp_acvp_response resp;
    size_t pk_size = pqcp_mlkem_pk_size(PQCP_MLKEM_768);
    size_t sk_size = pqcp_mlkem_sk_size(PQCP_MLKEM_768);
    size_t ct_size = pqcp_mlkem_ct_size(PQCP_MLKEM_768);
    uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
    uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
    uint8_t shared_secret[PQCP_MLKEM_SS_SIZE];

    zassert_equal(
        run_command("SEED:DRBG:0:%s", &resp,
                    "000102030405060708090a0b0c0d0e0f"
                    "101112131415161718191a1b1c1d1e1f"
                    "202122232425262728292a2b2c2d2e2f"),
        0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    assert_response_line(&resp, "RESULT:OK");

    zassert_equal(run_command("KEYGEN:MLKEM:768:", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, pk_size + sk_size);
    assert_response_prefix(&resp, "RESULT:");
    memcpy(pk, resp.data, pk_size);
    memcpy(sk, resp.data + pk_size, sk_size);

    bytes_to_hex(pk, pk_size, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("ENCAPS:MLKEM:768:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, ct_size + PQCP_MLKEM_SS_SIZE);
    assert_response_prefix(&resp, "RESULT:");
    memcpy(shared_secret, resp.data + ct_size, sizeof(shared_secret));

    memcpy(work_buffer, resp.data, ct_size);
    memcpy(work_buffer + ct_size, sk, sk_size);
    bytes_to_hex(work_buffer, ct_size + sk_size, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("DECAPS:MLKEM:768:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, PQCP_MLKEM_SS_SIZE);
    assert_response_prefix(&resp, "RESULT:");
    zassert_mem_equal(resp.data, shared_secret, PQCP_MLKEM_SS_SIZE);
}

ZTEST(pqcp_acvp_serial, test_mldsa_roundtrip_and_invalid_signature)
{
    struct pqcp_acvp_response resp;
    static const uint8_t message[] = "acvp-message";
    size_t pk_size = pqcp_mldsa_pk_size(PQCP_MLDSA_65);
    size_t sk_size = pqcp_mldsa_sk_size(PQCP_MLDSA_65);
    size_t sig_size = pqcp_mldsa_sig_size(PQCP_MLDSA_65);
    uint8_t pk[PQCP_MLDSA_PK_SIZE_MAX];
    uint8_t sk[PQCP_MLDSA_SK_SIZE_MAX];

    zassert_equal(
        run_command("SEED:DRBG:0:%s", &resp,
                    "f0e0d0c0b0a090807060504030201000"
                    "00112233445566778899aabbccddeeff"
                    "0102030405060708090a0b0c0d0e0f10"),
        0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    assert_response_line(&resp, "RESULT:OK");

    zassert_equal(run_command("KEYGEN:MLDSA:65:", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, pk_size + sk_size);
    assert_response_prefix(&resp, "RESULT:");
    memcpy(pk, resp.data, pk_size);
    memcpy(sk, resp.data + pk_size, sk_size);

    memcpy(work_buffer, sk, sk_size);
    memcpy(work_buffer + sk_size, message, sizeof(message) - 1U);
    bytes_to_hex(work_buffer, sk_size + sizeof(message) - 1U,
                 hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("SIGN:MLDSA:65:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, sig_size);
    assert_response_prefix(&resp, "RESULT:");

    memcpy(work_buffer, pk, pk_size);
    memcpy(work_buffer + pk_size, message, sizeof(message) - 1U);
    memcpy(work_buffer + pk_size + sizeof(message) - 1U, resp.data, sig_size);
    bytes_to_hex(work_buffer, pk_size + sig_size + sizeof(message) - 1U,
                 hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("VERIFY:MLDSA:65:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, 0U);
    assert_response_line(&resp, "RESULT:OK");

    work_buffer[pk_size + sizeof(message) - 1U + sig_size - 1U] ^= 0x01U;
    bytes_to_hex(work_buffer, pk_size + sig_size + sizeof(message) - 1U,
                 hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("VERIFY:MLDSA:65:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_VERIFY_INVALID);
    assert_response_line(&resp, "RESULT:INVALID");
}

ZTEST(pqcp_acvp_serial, test_rejects_malformed_commands)
{
    struct pqcp_acvp_response resp;

    zassert_equal(run_command("KEYGEN:MLKEM", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_MISSING_ARGS);
    assert_response_line(&resp, "ERROR:MISSING_ARGS");

    zassert_equal(run_command("KEYGEN:MLKEM:not-a-level:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_LEVEL);
    assert_response_line(&resp, "ERROR:INVALID_LEVEL");

    zassert_equal(run_command("KEYGEN:UNKNOWN:768:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_ALG);
    assert_response_line(&resp, "ERROR:INVALID_ALG");

    zassert_equal(run_command("KEYGEN:MLKEM:768:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
    assert_response_line(&resp, "ERROR:INVALID_CMD");

    zassert_equal(run_command("FOO:MLKEM:768:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
    assert_response_line(&resp, "ERROR:INVALID_CMD");

    zassert_equal(run_command("HELP:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
    assert_response_line(&resp, "ERROR:INVALID_CMD");

    zassert_equal(run_command("SELFTEST:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
    assert_response_line(&resp, "ERROR:INVALID_CMD");

    zassert_equal(run_command("VERIFY:MLDSA:65:00:11", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
    assert_response_line(&resp, "ERROR:INVALID_CMD");
}

ZTEST(pqcp_acvp_serial, test_rejects_invalid_hex_and_wrong_sizes)
{
    struct pqcp_acvp_response resp;

    zassert_equal(run_command("SEED:DRBG:0:abc", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_HEX);
    assert_response_line(&resp, "ERROR:INVALID_HEX");

    zassert_equal(run_command("ENCAPS:MLKEM:768:zz", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_HEX);
    assert_response_line(&resp, "ERROR:INVALID_HEX");

    zassert_equal(run_command("ENCAPS:MLKEM:999:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_LEVEL);
    assert_response_line(&resp, "ERROR:INVALID_LEVEL");

    zassert_equal(run_command("DECAPS:MLKEM:768:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");

    zassert_equal(run_command("VERIFY:MLDSA:65:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
    assert_response_line(&resp, "ERROR:WRONG_SIZE");
}

ZTEST(pqcp_acvp_serial, test_hex_decoder_rejects_oversize_payload)
{
    size_t out_len = 0U;
    uint8_t small_buffer[4];

    zassert_equal(
        pqcp_acvp_hex_to_bytes("001122334455", small_buffer, &out_len,
                               sizeof(small_buffer)),
        -ENOSPC);
}

ZTEST(pqcp_acvp_serial, test_help_and_selftest_commands)
{
    struct pqcp_acvp_response resp;

    zassert_equal(run_command("HELP::", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, 0U);
    assert_response_line(&resp, "RESULT:OK");

    zassert_equal(run_command("SELFTEST::", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, 0U);
    assert_response_line(&resp, "RESULT:OK");
}

ZTEST(pqcp_acvp_serial, test_result_strings_are_stable)
{
    static const struct {
        enum pqcp_acvp_result result;
        const char *expected;
    } cases[] = {
        { PQCP_ACVP_OK, "OK" },
        { PQCP_ACVP_ERR_INVALID_HEX, "INVALID_HEX" },
        { PQCP_ACVP_ERR_INVALID_LEVEL, "INVALID_LEVEL" },
        { PQCP_ACVP_ERR_INVALID_ALG, "INVALID_ALG" },
        { PQCP_ACVP_ERR_INVALID_CMD, "INVALID_CMD" },
        { PQCP_ACVP_ERR_MISSING_ARGS, "MISSING_ARGS" },
        { PQCP_ACVP_ERR_WRONG_SIZE, "WRONG_SIZE" },
        { PQCP_ACVP_ERR_KEYGEN, "KEYGEN_FAILED" },
        { PQCP_ACVP_ERR_ENCAPS, "ENCAPS_FAILED" },
        { PQCP_ACVP_ERR_DECAPS, "DECAPS_FAILED" },
        { PQCP_ACVP_ERR_SIGN, "SIGN_FAILED" },
        { PQCP_ACVP_ERR_VERIFY, "VERIFY_FAILED" },
        { PQCP_ACVP_ERR_SEED, "SEED_FAILED" },
        { PQCP_ACVP_ERR_NOT_ENABLED, "NOT_ENABLED" },
        { PQCP_ACVP_ERR_BUFFER_TOO_SMALL, "BUFFER_TOO_SMALL" },
        { PQCP_ACVP_VERIFY_INVALID, "INVALID" },
    };

    for (size_t i = 0U; i < ARRAY_SIZE(cases); ++i) {
        const char *result_str = pqcp_acvp_result_str(cases[i].result);

        zassert_not_null(result_str);
        zassert_equal(strcmp(result_str, cases[i].expected), 0,
                      "unexpected string for ACVP result %d",
                      (int)cases[i].result);
    }

    zassert_equal(strcmp(pqcp_acvp_result_str((enum pqcp_acvp_result)999),
                         "UNKNOWN"),
                  0);
}

ZTEST(pqcp_acvp_serial, test_response_formatter_serializes_public_wire_forms)
{
    struct pqcp_acvp_response resp;
    static uint8_t payload[] = { 0x00U, 0xabU, 0x7fU };

    pqcp_acvp_response_init(&resp, payload, sizeof(payload));

    resp.result = PQCP_ACVP_OK;
    resp.data_len = 0U;
    assert_response_line(&resp, "RESULT:OK");

    resp.result = PQCP_ACVP_VERIFY_INVALID;
    resp.data_len = 0U;
    assert_response_line(&resp, "RESULT:INVALID");

    resp.result = PQCP_ACVP_ERR_INVALID_CMD;
    resp.data_len = 0U;
    assert_response_line(&resp, "ERROR:INVALID_CMD");

    resp.result = PQCP_ACVP_OK;
    resp.data = payload;
    resp.data_len = sizeof(payload);
    assert_response_line(&resp, "RESULT:00ab7f");
}

ZTEST(pqcp_acvp_serial, test_response_formatter_rejects_tiny_buffer)
{
    struct pqcp_acvp_response resp;
    char tiny_buffer[4];

    pqcp_acvp_response_init(&resp, response_buffer, sizeof(response_buffer));
    resp.result = PQCP_ACVP_ERR_INVALID_CMD;

    zassert_equal(
        pqcp_acvp_format_response_line(&resp, tiny_buffer, sizeof(tiny_buffer)),
        -ENOSPC);
}

/*
 * Stress-oriented parser coverage is compiled only when overlay-fuzz.conf
 * enables CONFIG_PQCP_FUZZ_TESTS for this test image.
 */
#if defined(CONFIG_PQCP_FUZZ_TESTS)
static uint32_t fuzz_state = 0x8f23d91bU;

static uint32_t fuzz_next(void)
{
    fuzz_state = (1103515245U * fuzz_state) + 12345U;
    return fuzz_state;
}

ZTEST(pqcp_acvp_serial, test_stress_randomized_command_parsing)
{
    static const char *seed_hex =
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f";
    struct pqcp_acvp_response resp;
    int ret;

    for (size_t i = 0U; i < 64U; ++i) {
        switch (fuzz_next() % 8U) {
        case 0U:
            ret = run_command("HELP::", &resp);
            zassert_equal(ret, 0);
            break;
        case 1U:
            ret = run_command("SELFTEST::", &resp);
            zassert_equal(ret, 0);
            break;
        case 2U:
            ret = run_command("SEED:DRBG:0:%s", &resp, seed_hex);
            zassert_equal(ret, 0);
            break;
        case 3U:
            ret = run_command("KEYGEN:MLKEM:768:", &resp);
            zassert_equal(ret, 0);
            break;
        case 4U:
            ret = run_command("KEYGEN:MLDSA:65:", &resp);
            zassert_equal(ret, 0);
            break;
        case 5U:
            ret = run_command("VERIFY:MLDSA:65:xyz", &resp);
            zassert_true(ret < 0);
            break;
        case 6U:
            ret = run_command("ENCAPS:MLKEM:%u:00", &resp,
                              500U + (fuzz_next() % 700U));
            zassert_true(ret < 0);
            break;
        default:
            ret = run_command("NOPE:MLKEM:768:00:extra", &resp);
            zassert_true(ret < 0);
            break;
        }

        zassert_equal(pqcp_acvp_format_response_line(&resp, response_line,
                                                     sizeof(response_line)),
                      0);
        zassert_true(strncmp(response_line, "RESULT:", 7) == 0 ||
                     strncmp(response_line, "ERROR:", 6) == 0,
                     "unexpected response format: %s", response_line);
    }
}
#endif

static void *pqcp_acvp_setup(void)
{
    return NULL;
}

ZTEST_SUITE(pqcp_acvp_serial, NULL, pqcp_acvp_setup, NULL, NULL, NULL);
