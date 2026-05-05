/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - PQClean baseline RNG glue
 *
 * The vendored clean baseline uses PQClean's `PQCLEAN_randombytes` symbol.
 * We route that symbol through the existing PQCP RNG abstraction so baseline
 * comparisons use the same Zephyr/PSA/custom entropy plumbing as the default
 * PQCP provider family.
 */

#include <pqcp_zephyr/rng.h>

int PQCLEAN_randombytes(uint8_t *output, size_t n)
{
    return pqcp_rng_get_bytes(output, n);
}
