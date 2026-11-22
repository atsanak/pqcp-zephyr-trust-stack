/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Stand-in for <valgrind/memcheck.h>. mldsa-native annotates every point where
 * secret-derived data becomes public with MLD_CT_TESTING_DECLASSIFY, which
 * (with MLD_CONFIG_CT_TESTING_ENABLED) expands to VALGRIND_MAKE_MEM_DEFINED.
 * Here that macro reports the event to the pqcp_ct_trace TCG plugin instead,
 * so the upstream annotations become trace-segment boundaries without any
 * change to the vendored library.
 */
#ifndef PQCP_CT_SHIM_MEMCHECK_H
#define PQCP_CT_SHIM_MEMCHECK_H

#include <stddef.h>

void pqcp_ct_declassify(const void *ptr, size_t len);

#define VALGRIND_MAKE_MEM_DEFINED(ptr, len) pqcp_ct_declassify((ptr), (len))
#define VALGRIND_MAKE_MEM_UNDEFINED(ptr, len)                                  \
	do {                                                                   \
		(void)(ptr);                                                   \
		(void)(len);                                                   \
	} while (0)

#endif
