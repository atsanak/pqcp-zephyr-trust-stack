/*
 * SPDX-License-Identifier: MIT
 *
 * Tests for the extended firmware capability plane.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/capability_extension.h>

ZTEST(pqcp_capability_extension, test_current_reflects_compiled_modules)
{
	uint32_t ext = pqcp_capability_evidence_ext_current();

	/* This image enables exactly the extension plane itself and the
	 * tamper engine; every other extended module is compiled out.
	 */
	zassert_true((ext & PQCP_CAPABILITY_EXT_CAPABILITY_EXTENSION) != 0U);
	zassert_true((ext & PQCP_CAPABILITY_EXT_TAMPER_ENGINE) != 0U);
	zassert_equal(ext & ~(PQCP_CAPABILITY_EXT_CAPABILITY_EXTENSION |
			      PQCP_CAPABILITY_EXT_TAMPER_ENGINE),
		      0U);
	zassert_equal(ext & ~PQCP_CAPABILITY_EXT_KNOWN_MASK, 0U);
}

ZTEST(pqcp_capability_extension, test_current_summary_binds_base_word)
{
	struct pqcp_capability_extension extension;

	zassert_equal(pqcp_capability_extension_current(&extension), 0);
	zassert_equal(extension.schema_version,
		      PQCP_CAPABILITY_EXTENSION_SCHEMA_VERSION);
	zassert_equal(extension.base_capabilities,
		      pqcp_capability_evidence_capabilities_current());
	zassert_equal(extension.ext_capabilities,
		      pqcp_capability_evidence_ext_current());
	zassert_equal(extension.ext_known_mask,
		      PQCP_CAPABILITY_EXT_KNOWN_MASK);
	zassert_equal(extension.ext_count, 2U);
	/* This image compiles only part of the base evidence stack. */
	zassert_equal(extension.base_full,
		      (extension.base_capabilities &
		       PQCP_CAPABILITY_EVIDENCE_KNOWN_MASK) ==
			      PQCP_CAPABILITY_EVIDENCE_KNOWN_MASK);

	zassert_equal(pqcp_capability_extension_current(NULL), -EINVAL);
}

ZTEST(pqcp_capability_extension, test_emit_accepts_genuine_summary)
{
	struct pqcp_capability_extension extension;

	zassert_equal(pqcp_capability_extension_current(&extension), 0);
	zassert_equal(pqcp_capability_extension_emit(&extension), 0);
}

ZTEST(pqcp_capability_extension, test_emit_rejects_tampered_summary)
{
	struct pqcp_capability_extension extension;

	zassert_equal(pqcp_capability_extension_emit(NULL), -EINVAL);

	zassert_equal(pqcp_capability_extension_current(&extension), 0);
	extension.schema_version = 99U;
	zassert_equal(pqcp_capability_extension_emit(&extension), -EINVAL);

	zassert_equal(pqcp_capability_extension_current(&extension), 0);
	extension.ext_capabilities |= 0x80000000U;
	zassert_equal(pqcp_capability_extension_emit(&extension), -EINVAL);

	zassert_equal(pqcp_capability_extension_current(&extension), 0);
	extension.ext_known_mask = 0xffffffffU;
	zassert_equal(pqcp_capability_extension_emit(&extension), -EINVAL);

	zassert_equal(pqcp_capability_extension_current(&extension), 0);
	extension.ext_count = 33U;
	zassert_equal(pqcp_capability_extension_emit(&extension), -EINVAL);
}

ZTEST_SUITE(pqcp_capability_extension, NULL, NULL, NULL, NULL, NULL);
