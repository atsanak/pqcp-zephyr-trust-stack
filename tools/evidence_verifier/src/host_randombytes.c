/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * randombytes stub for the host evidence verifier.
 *
 * The verifier only ever calls crypto_sign_verify, which needs no
 * randomness. mldsa-native still links against randombytes for the keygen
 * and signing paths, so this stub satisfies the linker and aborts loudly if
 * anything ever reaches it.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int randombytes(uint8_t *out, size_t outlen);

int randombytes(uint8_t *out, size_t outlen)
{
	(void)out;
	(void)outlen;
	fprintf(stderr,
		"pqcp-evidence-verify: randombytes called in verify-only tool\n");
	abort();
}
