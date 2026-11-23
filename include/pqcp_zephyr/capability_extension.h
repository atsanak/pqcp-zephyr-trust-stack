/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Extended firmware capability plane
 *
 * Stability: experimental evidence API. The base 32-bit evidence capability
 * mask in the capability descriptor is fully allocated (bits 0..31). This
 * module adds a second, independently versioned 32-bit capability word for
 * evidence modules introduced after the base mask filled, and emits one
 * compact PQCP_CAPABILITY_EXTENSION marker binding the base word to the
 * extension word. It is evidence metadata only: it performs no cryptographic
 * operation, uses no dynamic allocation, and never alters the base
 * capability descriptor marker.
 */

#ifndef PQCP_ZEPHYR_CAPABILITY_EXTENSION_H_
#define PQCP_ZEPHYR_CAPABILITY_EXTENSION_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/capability_descriptor.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schema version for PQCP_CAPABILITY_EXTENSION transcript markers. */
#define PQCP_CAPABILITY_EXTENSION_SCHEMA_VERSION 1U

/** The extended capability plane itself is compiled into this image. */
#define PQCP_CAPABILITY_EXT_CAPABILITY_EXTENSION    (1U << 0)
/** Deployment marker render-to-buffer support is compiled in. */
#define PQCP_CAPABILITY_EXT_MARKER_RENDER           (1U << 1)
/** Deterministic evidence tamper engine is compiled in. */
#define PQCP_CAPABILITY_EXT_TAMPER_ENGINE           (1U << 2)
/** Adversarial tamper detection matrix is compiled in. */
#define PQCP_CAPABILITY_EXT_TAMPER_MATRIX           (1U << 3)
/** Tamper matrix replay verifier is compiled in. */
#define PQCP_CAPABILITY_EXT_TAMPER_MATRIX_REPLAY    (1U << 4)
/** Tamper matrix replay audit aggregation is compiled in. */
#define PQCP_CAPABILITY_EXT_TAMPER_MATRIX_AUDIT     (1U << 5)
/** Hash-chained evidence trail commitment is compiled in. */
#define PQCP_CAPABILITY_EXT_EVIDENCE_TRAIL          (1U << 6)
/** Evidence trail replay verifier is compiled in. */
#define PQCP_CAPABILITY_EXT_EVIDENCE_TRAIL_REPLAY   (1U << 7)
/** Evidence trail replay audit aggregation is compiled in. */
#define PQCP_CAPABILITY_EXT_EVIDENCE_TRAIL_AUDIT    (1U << 8)

/** All extended capability bits known by this API version. */
#define PQCP_CAPABILITY_EXT_KNOWN_MASK \
	(PQCP_CAPABILITY_EXT_CAPABILITY_EXTENSION | \
	 PQCP_CAPABILITY_EXT_MARKER_RENDER | \
	 PQCP_CAPABILITY_EXT_TAMPER_ENGINE | \
	 PQCP_CAPABILITY_EXT_TAMPER_MATRIX | \
	 PQCP_CAPABILITY_EXT_TAMPER_MATRIX_REPLAY | \
	 PQCP_CAPABILITY_EXT_TAMPER_MATRIX_AUDIT | \
	 PQCP_CAPABILITY_EXT_EVIDENCE_TRAIL | \
	 PQCP_CAPABILITY_EXT_EVIDENCE_TRAIL_REPLAY | \
	 PQCP_CAPABILITY_EXT_EVIDENCE_TRAIL_AUDIT)

/**
 * @brief Extended firmware capability summary.
 *
 * The extension is evidence metadata only. It does not claim certification,
 * does not prove side-channel security, and does not select crypto providers.
 */
struct pqcp_capability_extension {
	/** Marker schema version. */
	uint32_t schema_version;
	/** Base evidence capability word from the capability descriptor. */
	uint32_t base_capabilities;
	/** Extended evidence capability word for post-base modules. */
	uint32_t ext_capabilities;
	/** Extended capability bits known by this firmware image. */
	uint32_t ext_known_mask;
	/** Number of extended capability bits set in this image. */
	uint32_t ext_count;
	/** True when every base capability bit is present. */
	bool base_full;
};

/**
 * @brief Return compiled-in extended capability bits for the current image.
 *
 * @return PQCP_CAPABILITY_EXT_* bit mask.
 */
uint32_t pqcp_capability_evidence_ext_current(void);

/**
 * @brief Populate the extended capability summary for the current image.
 *
 * @param extension Output summary. Must not be NULL.
 *
 * @retval 0 on success.
 * @retval -EINVAL on NULL output.
 */
int pqcp_capability_extension_current(
	struct pqcp_capability_extension *extension);

/**
 * @brief Emit one stable PQCP_CAPABILITY_EXTENSION marker.
 *
 * @param extension Extension summary built by
 *                  pqcp_capability_extension_current().
 *
 * @retval 0 on success.
 * @retval -EINVAL on NULL, schema, or range violations.
 */
int pqcp_capability_extension_emit(
	const struct pqcp_capability_extension *extension);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_CAPABILITY_EXTENSION_H_ */
