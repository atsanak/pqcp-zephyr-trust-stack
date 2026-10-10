/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */
#ifndef PQCP_MBEDTLS_THREADING_ALT_H_
#define PQCP_MBEDTLS_THREADING_ALT_H_

/* Mbed TLS 4 / TF-PSA 1.x platform types, not the legacy 3.x mutex ABI. */
#include <zephyr/kernel.h>
typedef struct k_mutex mbedtls_platform_mutex_t;
typedef struct k_condvar mbedtls_platform_condition_variable_t;

#endif
