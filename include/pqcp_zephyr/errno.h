/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Portable errno compatibility for security-specific failure results.
 */

#ifndef PQCP_ZEPHYR_ERRNO_H_
#define PQCP_ZEPHYR_ERRNO_H_

#include <errno.h>

/*
 * Linux exposes dedicated key-management errno values while several Zephyr
 * libc configurations do not. Preserve the API contract and map the missing
 * names to portable errors with equivalent caller behavior.
 */
#ifndef EKEYREJECTED
#define EKEYREJECTED EACCES
#endif

#ifndef EKEYEXPIRED
#define EKEYEXPIRED ETIMEDOUT
#endif

#ifndef EKEYREVOKED
#define EKEYREVOKED EACCES
#endif

#ifndef ENOKEY
#define ENOKEY ENOENT
#endif

#endif /* PQCP_ZEPHYR_ERRNO_H_ */
