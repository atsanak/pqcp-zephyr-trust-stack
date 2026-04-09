/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP ACVP command library tests
 */

#include <zephyr/ztest.h>
#include <zephyr/sys/printk.h>

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

    zassert_equal(run_command("KEYGEN:MLKEM:768:", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, pk_size + sk_size);
    memcpy(pk, resp.data, pk_size);
    memcpy(sk, resp.data + pk_size, sk_size);

    bytes_to_hex(pk, pk_size, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("ENCAPS:MLKEM:768:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, ct_size + PQCP_MLKEM_SS_SIZE);
    memcpy(shared_secret, resp.data + ct_size, sizeof(shared_secret));

    memcpy(work_buffer, resp.data, ct_size);
    memcpy(work_buffer + ct_size, sk, sk_size);
    bytes_to_hex(work_buffer, ct_size + sk_size, hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("DECAPS:MLKEM:768:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, PQCP_MLKEM_SS_SIZE);
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

    zassert_equal(run_command("KEYGEN:MLDSA:65:", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, pk_size + sk_size);
    memcpy(pk, resp.data, pk_size);
    memcpy(sk, resp.data + pk_size, sk_size);

    memcpy(work_buffer, sk, sk_size);
    memcpy(work_buffer + sk_size, message, sizeof(message) - 1U);
    bytes_to_hex(work_buffer, sk_size + sizeof(message) - 1U,
                 hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("SIGN:MLDSA:65:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, sig_size);

    memcpy(work_buffer, pk, pk_size);
    memcpy(work_buffer + pk_size, message, sizeof(message) - 1U);
    memcpy(work_buffer + pk_size + sizeof(message) - 1U, resp.data, sig_size);
    bytes_to_hex(work_buffer, pk_size + sig_size + sizeof(message) - 1U,
                 hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("VERIFY:MLDSA:65:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, 0U);

    work_buffer[pk_size + sizeof(message) - 1U + sig_size - 1U] ^= 0x01U;
    bytes_to_hex(work_buffer, pk_size + sig_size + sizeof(message) - 1U,
                 hex_buffer, sizeof(hex_buffer));
    zassert_equal(run_command("VERIFY:MLDSA:65:%s", &resp, hex_buffer), 0);
    zassert_equal(resp.result, PQCP_ACVP_VERIFY_INVALID);
}

ZTEST(pqcp_acvp_serial, test_rejects_malformed_commands)
{
    struct pqcp_acvp_response resp;

    zassert_equal(run_command("KEYGEN:MLKEM", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_MISSING_ARGS);

    zassert_equal(run_command("KEYGEN:MLKEM:not-a-level:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_LEVEL);

    zassert_equal(run_command("KEYGEN:UNKNOWN:768:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_ALG);

    zassert_equal(run_command("KEYGEN:MLKEM:768:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);

    zassert_equal(run_command("FOO:MLKEM:768:", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_CMD);
}

ZTEST(pqcp_acvp_serial, test_rejects_invalid_hex_and_wrong_sizes)
{
    struct pqcp_acvp_response resp;

    zassert_equal(run_command("SEED:DRBG:0:abc", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_HEX);

    zassert_equal(run_command("ENCAPS:MLKEM:768:zz", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_HEX);

    zassert_equal(run_command("ENCAPS:MLKEM:999:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_INVALID_LEVEL);

    zassert_equal(run_command("DECAPS:MLKEM:768:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);

    zassert_equal(run_command("VERIFY:MLDSA:65:00", &resp), -EINVAL);
    zassert_equal(resp.result, PQCP_ACVP_ERR_WRONG_SIZE);
}

ZTEST(pqcp_acvp_serial, test_help_and_selftest_commands)
{
    struct pqcp_acvp_response resp;

    zassert_equal(run_command("HELP::", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, 0U);

    zassert_equal(run_command("SELFTEST::", &resp), 0);
    zassert_equal(resp.result, PQCP_ACVP_OK);
    zassert_equal(resp.data_len, 0U);
}

static void *pqcp_acvp_setup(void)
{
    return NULL;
}

ZTEST_SUITE(pqcp_acvp_serial, NULL, pqcp_acvp_setup, NULL, NULL, NULL);
