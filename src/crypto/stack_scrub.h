/* SPDX-License-Identifier: MIT */
/*
 * Overwrite the stack below the caller.
 *
 * Secret handling calls leave copies of intermediate values in dead stack
 * frames. PQCP_DEFINE_STACK_SCRUB(name, bytes) defines a function that
 * overwrites `bytes` of stack with zero words. The volatile array forces real
 * stores that the compiler may not drop and the empty asm makes the array
 * observable so it is not optimised away. The caller needs `bytes` of stack
 * headroom. The depth is measured for each primitive, not proven.
 */
#ifndef PQCP_STACK_SCRUB_H
#define PQCP_STACK_SCRUB_H

#include <stddef.h>
#include <stdint.h>

#define PQCP_DEFINE_STACK_SCRUB(name, bytes)                                  \
	static void __attribute__((noinline)) name(void)                      \
	{                                                                     \
		volatile uint32_t pad[(bytes) / 4U];                          \
                                                                              \
		for (size_t i = 0U; i < sizeof(pad) / sizeof(pad[0]); ++i) {  \
			pad[i] = 0U;                                          \
		}                                                             \
		__asm__ volatile("" : : "r"(pad) : "memory");                 \
	}

#endif /* PQCP_STACK_SCRUB_H */
