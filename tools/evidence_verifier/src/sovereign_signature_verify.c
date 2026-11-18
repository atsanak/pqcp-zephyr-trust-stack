/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */
#include <stdint.h>
#include <stdio.h>
#include "mldsa_native.h"

int main(void)
{
    uint8_t input[1952 + 32 + 3309];
    static const uint8_t context[] = "pqcp-sovereign-audit-batch-v1";
    if (fread(input, 1, sizeof(input), stdin) != sizeof(input) ||
        fgetc(stdin) != EOF || ferror(stdin)) {
        return 2;
    }
    return crypto_sign_verify(input + 1952 + 32, 3309, input + 1952, 32,
                              context, sizeof(context) - 1, input) == 0 ? 0 : 1;
}
