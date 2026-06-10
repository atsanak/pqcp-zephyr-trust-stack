/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Host shim for <zephyr/sys/printk.h>.
 *
 * The firmware evidence verifiers are deliberately freestanding C whose only
 * Zephyr dependency is printk/snprintk. Mapping both onto the hosted stdio
 * equivalents lets the UNMODIFIED firmware .c files compile into the host
 * evidence-verifier CLI, so the parsing and digest-recomputation logic that
 * runs on device is byte-for-byte the logic that verifies transcripts on
 * host. Do not add behavior here: this file must stay a pure aliasing shim.
 */

#ifndef PQCP_HOST_SHIM_ZEPHYR_SYS_PRINTK_H_
#define PQCP_HOST_SHIM_ZEPHYR_SYS_PRINTK_H_

#include <stdio.h>

#define printk printf
#define snprintk snprintf

#endif /* PQCP_HOST_SHIM_ZEPHYR_SYS_PRINTK_H_ */
