/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment marker render-to-buffer support
 *
 * Stability: experimental evidence API. This module renders the terminal
 * deployment evidence markers (final verdict, terminal seal, assurance
 * passport) into caller-owned buffers using exactly the field set and
 * key=value layout consumed by the corresponding replay verifiers. It exists
 * so firmware can adversarially re-verify its own markers in-image: a
 * rendered marker fed back into the matching replay verifier must pass, and
 * any deterministic mutation of it must be rejected. It performs no
 * cryptographic operation and uses no dynamic allocation.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_MARKER_RENDER_H_
#define PQCP_ZEPHYR_DEPLOYMENT_MARKER_RENDER_H_

#include <stddef.h>

#include <pqcp_zephyr/deployment_assurance_passport.h>
#include <pqcp_zephyr/deployment_evidence_seal.h>
#include <pqcp_zephyr/deployment_evidence_verdict.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Minimum buffer size guaranteed to hold any rendered terminal marker. */
#define PQCP_DEPLOYMENT_MARKER_RENDER_LINE_MAX 1024U

/**
 * @brief Render the final deployment evidence verdict marker into a buffer.
 *
 * The rendered line carries the identical field set the verdict emit path
 * prints and the verdict replay verifier parses, without a trailing newline.
 *
 * @param verdict Final evidence verdict. Validated like the emit path.
 * @param out Output buffer for the rendered marker line.
 * @param out_size Output buffer capacity in bytes.
 *
 * @retval >0 number of characters rendered.
 * @retval -EINVAL on NULL or invalid verdict fields.
 * @retval -ENOSPC when the buffer is too small.
 */
int pqcp_deployment_marker_render_verdict(
	const struct pqcp_deployment_evidence_verdict *verdict,
	char *out, size_t out_size);

/**
 * @brief Render the terminal deployment evidence seal marker into a buffer.
 *
 * @param seal Terminal evidence seal. Validated like the emit path.
 * @param out Output buffer for the rendered marker line.
 * @param out_size Output buffer capacity in bytes.
 *
 * @retval >0 number of characters rendered.
 * @retval -EINVAL on NULL or invalid seal fields.
 * @retval -ENOSPC when the buffer is too small.
 */
int pqcp_deployment_marker_render_seal(
	const struct pqcp_deployment_evidence_seal *seal,
	char *out, size_t out_size);

/**
 * @brief Render the deployment assurance passport marker into a buffer.
 *
 * @param passport Assurance passport. Validated like the emit path.
 * @param out Output buffer for the rendered marker line.
 * @param out_size Output buffer capacity in bytes.
 *
 * @retval >0 number of characters rendered.
 * @retval -EINVAL on NULL or invalid passport fields.
 * @retval -ENOSPC when the buffer is too small.
 */
int pqcp_deployment_marker_render_passport(
	const struct pqcp_deployment_assurance_passport *passport,
	char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_MARKER_RENDER_H_ */
