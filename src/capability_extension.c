/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Extended firmware capability plane for post-base evidence modules.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/capability_extension.h>

uint32_t pqcp_capability_evidence_ext_current(void)
{
	uint32_t ext = 0U;

	if (IS_ENABLED(CONFIG_PQCP_CAPABILITY_EXTENSION)) {
		ext |= PQCP_CAPABILITY_EXT_CAPABILITY_EXTENSION;
	}
	if (IS_ENABLED(CONFIG_PQCP_DEPLOYMENT_MARKER_RENDER)) {
		ext |= PQCP_CAPABILITY_EXT_MARKER_RENDER;
	}
	if (IS_ENABLED(CONFIG_PQCP_DEPLOYMENT_TAMPER_ENGINE)) {
		ext |= PQCP_CAPABILITY_EXT_TAMPER_ENGINE;
	}
	if (IS_ENABLED(CONFIG_PQCP_DEPLOYMENT_TAMPER_MATRIX)) {
		ext |= PQCP_CAPABILITY_EXT_TAMPER_MATRIX;
	}
	if (IS_ENABLED(CONFIG_PQCP_DEPLOYMENT_TAMPER_MATRIX_REPLAY)) {
		ext |= PQCP_CAPABILITY_EXT_TAMPER_MATRIX_REPLAY;
	}
	if (IS_ENABLED(CONFIG_PQCP_DEPLOYMENT_TAMPER_MATRIX_AUDIT)) {
		ext |= PQCP_CAPABILITY_EXT_TAMPER_MATRIX_AUDIT;
	}
	if (IS_ENABLED(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_TRAIL)) {
		ext |= PQCP_CAPABILITY_EXT_EVIDENCE_TRAIL;
	}
	if (IS_ENABLED(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_TRAIL_REPLAY)) {
		ext |= PQCP_CAPABILITY_EXT_EVIDENCE_TRAIL_REPLAY;
	}
	if (IS_ENABLED(CONFIG_PQCP_DEPLOYMENT_EVIDENCE_TRAIL_AUDIT)) {
		ext |= PQCP_CAPABILITY_EXT_EVIDENCE_TRAIL_AUDIT;
	}

	return ext;
}

static uint32_t popcount_u32(uint32_t value)
{
	uint32_t count = 0U;

	while (value != 0U) {
		count += value & 1U;
		value >>= 1U;
	}

	return count;
}

int pqcp_capability_extension_current(
	struct pqcp_capability_extension *extension)
{
	if (extension == NULL) {
		return -EINVAL;
	}

	memset(extension, 0, sizeof(*extension));
	extension->schema_version = PQCP_CAPABILITY_EXTENSION_SCHEMA_VERSION;
	extension->base_capabilities =
		pqcp_capability_evidence_capabilities_current();
	extension->ext_capabilities = pqcp_capability_evidence_ext_current();
	extension->ext_known_mask = PQCP_CAPABILITY_EXT_KNOWN_MASK;
	extension->ext_count = popcount_u32(extension->ext_capabilities);
	extension->base_full =
		(extension->base_capabilities &
		 PQCP_CAPABILITY_EVIDENCE_KNOWN_MASK) ==
		PQCP_CAPABILITY_EVIDENCE_KNOWN_MASK;

	return 0;
}

int pqcp_capability_extension_emit(
	const struct pqcp_capability_extension *extension)
{
	if (extension == NULL ||
	    extension->schema_version !=
		    PQCP_CAPABILITY_EXTENSION_SCHEMA_VERSION ||
	    (extension->ext_capabilities & ~extension->ext_known_mask) != 0U ||
	    extension->ext_known_mask != PQCP_CAPABILITY_EXT_KNOWN_MASK ||
	    extension->ext_count > 32U) {
		return -EINVAL;
	}

	printk("PQCP_CAPABILITY_EXTENSION schema=%u base=0x%08x ext=0x%08x ext_known=0x%08x ext_count=%u base_full=%u\n",
	       extension->schema_version,
	       extension->base_capabilities,
	       extension->ext_capabilities,
	       extension->ext_known_mask,
	       extension->ext_count,
	       extension->base_full ? 1U : 0U);

	return 0;
}
