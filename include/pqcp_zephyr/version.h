/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * PQCP Zephyr Trust Stack - Version Information
 */

#ifndef PQCP_ZEPHYR_VERSION_H_
#define PQCP_ZEPHYR_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Major version of the PQCP Zephyr module. */
#define PQCP_VERSION_MAJOR 1

/** @brief Minor version of the PQCP Zephyr module. */
#define PQCP_VERSION_MINOR 0

/** @brief Patch version of the PQCP Zephyr module. */
#define PQCP_VERSION_PATCH 0

/** @brief Packed semantic version for simple compile-time comparisons. */
#define PQCP_VERSION_HEX \
    ((PQCP_VERSION_MAJOR << 16) | (PQCP_VERSION_MINOR << 8) | PQCP_VERSION_PATCH)

/** @brief Human-readable semantic version string. */
#define PQCP_VERSION_STRING "1.0.0"

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_VERSION_H_ */
