/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Serial ACVP Sample
 *
 * UART/Serial interface for running ACVP test vectors.
 * Accepts commands via serial and returns results for ACVP validation.
 *
 * Protocol:
 *   Input:  CMD:ALG:LEVEL:HEX_DATA
 *   Output: RESULT:HEX_DATA or ERROR:CODE
 *
 * Commands:
 *   SEED:DRBG:0:hexseed - Seed deterministic RNG
 *   KEYGEN:MLKEM:768:   - Generate ML-KEM keypair
 *   ENCAPS:MLKEM:768:pk - Encapsulate to public key
 *   DECAPS:MLKEM:768:ctsk - Decapsulate ciphertext with secret key
 *   KEYGEN:MLDSA:65:    - Generate ML-DSA keypair
 *   SIGN:MLDSA:65:skmsg - Sign message with secret key
 *   VERIFY:MLDSA:65:pkmsgsig - Verify signature
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/console/console.h>
#include <pqcp_zephyr/acvp_cmd.h>
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

#include <string.h>

#define MAX_RESPONSE_DATA_LEN PQCP_ACVP_RESPONSE_BYTES_MAX
#define MAX_INPUT_DATA_LEN    PQCP_ACVP_INPUT_BYTES_MAX
#define MAX_LINE_LEN         ((MAX_INPUT_DATA_LEN * 2U) + 64U)

/* Working buffer for hex decoding */
static uint8_t work_buffer[MAX_INPUT_DATA_LEN];

/* Response buffer for output data */
static uint8_t response_buffer[MAX_RESPONSE_DATA_LEN];

/* Hex output buffer (2x data + null) */
static char response_line[(MAX_RESPONSE_DATA_LEN * 2U) + 64U];

/* Line input buffer */
static char line_buffer[MAX_LINE_LEN];

/* Print help text */
static void print_help(void)
{
    printk("Commands:\n");
    printk("  SEED:DRBG:0:<hexseed>     - Seed deterministic RNG\n");
    printk("  KEYGEN:MLKEM:<512|768|1024>: - Generate ML-KEM keypair\n");
    printk("  ENCAPS:MLKEM:<level>:<pk>    - Encapsulate with public key\n");
    printk("  DECAPS:MLKEM:<level>:<ct||sk> - Decapsulate ciphertext\n");
    printk("  KEYGEN:MLDSA:<44|65|87>:  - Generate ML-DSA keypair\n");
    printk("  SIGN:MLDSA:<level>:<sk||msg> - Sign message\n");
    printk("  VERIFY:MLDSA:<level>:<pk||msg||sig> - Verify signature\n");
    printk("  SELFTEST::                - Run internal self-test\n");
    printk("RESULT:OK\n");
}

static bool is_help_command(const char *line)
{
    return strcmp(line, "HELP") == 0 || strcmp(line, "HELP::") == 0;
}

/* Process and respond to a command */
static void process_and_respond(char *line)
{
    size_t line_len = strlen(line);

    while (line_len > 0U &&
           (line[line_len - 1U] == '\r' || line[line_len - 1U] == '\n')) {
        line[--line_len] = '\0';
    }

    if (line_len == 0U) {
        return;
    }

    /* Special case: HELP command */
    if (is_help_command(line)) {
        print_help();
        return;
    }
    
    /* Initialize response */
    struct pqcp_acvp_response resp;
    pqcp_acvp_response_init(&resp, response_buffer, sizeof(response_buffer));
    
    /* Process the command */
    pqcp_acvp_process_command(line, work_buffer, sizeof(work_buffer), &resp);
    
    if (pqcp_acvp_format_response_line(&resp, response_line,
                                       sizeof(response_line)) != 0) {
        printk("ERROR:%s\n",
               pqcp_acvp_result_str(PQCP_ACVP_ERR_BUFFER_TOO_SMALL));
        return;
    }

    printk("%s\n", response_line);
}

int main(void)
{
    printk("\n");
    printk("PQCP Serial ACVP Interface\n");
    printk("==========================\n");
    printk("Ready for commands. Format: CMD:ALG:LEVEL:HEX_DATA\n");
    printk("Commands: SEED, KEYGEN, ENCAPS, DECAPS, SIGN, VERIFY, SELFTEST, HELP\n");
    printk("\n");
    
    /* Initialize RNG */
    pqcp_rng_init();
    
    console_init();
    
    while (1) {
        printk("> ");
        
        /* Read line from console */
        int len = 0;
        bool overflow = false;
        char c;
        
        while (1) {
            c = console_getchar();
            
            if (c == '\r' || c == '\n') {
                break;
            }
            
            if ((c == '\b' || c == 0x7f) && len > 0) {
                len--;
                continue;
            }

            if (!overflow && len < MAX_LINE_LEN - 1) {
                line_buffer[len++] = c;
            } else {
                overflow = true;
            }
        }
        
        line_buffer[len] = '\0';

        if (overflow) {
            printk("ERROR:%s\n",
                   pqcp_acvp_result_str(PQCP_ACVP_ERR_BUFFER_TOO_SMALL));
            continue;
        }

        if (len > 0) {
            process_and_respond(line_buffer);
        }
    }
    
    return 0;
}
