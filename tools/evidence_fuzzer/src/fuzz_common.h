/*
 * SPDX-License-Identifier: MIT
 *
 * State shared between the evidence-grammar harness (main.c) and the binary
 * parser targets (binary_targets.c): the seeded PRNG and the edge-coverage
 * "new edge" flag maintained by the SanitizerCoverage callbacks.
 */

#ifndef PQCP_FUZZ_COMMON_H_
#define PQCP_FUZZ_COMMON_H_

#include <stddef.h>
#include <stdint.h>

uint64_t rng_next(void);
uint32_t rng_below(uint32_t bound);

/* Set to 1 by the coverage callbacks whenever an unseen edge is reached. */
extern volatile int new_edge_this_run;

/*
 * Binary (length-delimited) parser targets: fleet CBOR, COSE_Sign1,
 * COSE_Key and the policy module codec. Each input is an arbitrary byte
 * string, not a C string, so these run as a second coverage-guided
 * campaign sharing the PRNG and the edge map.
 */
#define BINARY_TARGET_COUNT 4U

/* Build the seed corpus from the real encoders. Returns 0 on success. */
int binary_seed_corpus(void);
size_t binary_corpus_size(void);

/*
 * Regression pass over every seed, then `iterations` mutated inputs with
 * new-edge promotion. Aborts the process (after dumping the reproducer) on
 * any violated invariant; sanitizers abort on memory errors and UB.
 */
void binary_campaign(unsigned long iterations);

/* One line: how many inputs each binary parser accepted. */
void binary_print_stats(void);

#endif /* PQCP_FUZZ_COMMON_H_ */
