/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Build-only assurance status sample.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/assurance.h>
#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/evidence_session.h>
#include <pqcp_zephyr/firmware_policy.h>
#include <pqcp_zephyr/provider.h>

#include <pqcp_assurance_digest_generated.h>

static struct pqcp_assurance_artifact
	pqcp_sample_artifacts[ARRAY_SIZE(pqcp_assurance_digest_artifact_names)];

static void pqcp_sample_populate_artifacts(void)
{
	for (size_t i = 0; i < PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT; ++i) {
		pqcp_sample_artifacts[i].name =
			pqcp_assurance_digest_artifact_names[i];
		pqcp_sample_artifacts[i].sha256 =
			pqcp_assurance_digest_artifact_sha256[i];
	}
}

int main(void)
{
	struct pqcp_evidence_session session;
	const struct pqcp_assurance_manifest manifest = {
		.version = PQCP_ASSURANCE_DIGEST_VERSION,
		.digest_sha256 = PQCP_ASSURANCE_DIGEST_ROOT_SHA256,
		.schema_version = PQCP_ASSURANCE_DIGEST_SCHEMA_VERSION,
		.artifacts = PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT > 0 ?
			pqcp_sample_artifacts : NULL,
		.artifact_count = PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT,
	};
	const uint32_t required_events =
		PQCP_EVIDENCE_EVENT_BUILD_MANIFEST |
		PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT |
		PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY |
		PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS |
		PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE;
	int ret;

	pqcp_sample_populate_artifacts();

	if (pqcp_evidence_session_begin(&session, required_events) != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}

	ret = pqcp_build_manifest_emit();
	if ((pqcp_evidence_session_record(
		     &session, PQCP_EVIDENCE_EVENT_BUILD_MANIFEST, ret) != 0) ||
	    (ret != 0)) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}

	ret = pqcp_provider_emit_contract();
	if ((pqcp_evidence_session_record(
		     &session, PQCP_EVIDENCE_EVENT_PROVIDER_CONTRACT, ret) != 0) ||
	    (ret != 0)) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}

	ret = pqcp_firmware_policy_emit_current();
	if ((pqcp_evidence_session_record(
		     &session, PQCP_EVIDENCE_EVENT_FIRMWARE_POLICY, ret) != 0) ||
	    (ret != 0)) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}

	ret = pqcp_assurance_emit_status(&manifest);
	if ((pqcp_evidence_session_record(
		     &session, PQCP_EVIDENCE_EVENT_ASSURANCE_STATUS, ret) != 0) ||
	    (ret != 0)) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}
	if (manifest.artifact_count > 0U) {
		ret = pqcp_evidence_session_record(
			&session, PQCP_EVIDENCE_EVENT_ASSURANCE_ARTIFACTS, 0);
		if (ret != 0) {
			printk("PROJECT EXECUTION FAILED\n");
			return 1;
		}
	}

	ret = pqcp_assurance_emit_device_evidence(
		&manifest,
		PQCP_ASSURANCE_DEVICE_EVIDENCE_NONCE,
		PQCP_ASSURANCE_DEVICE_EVIDENCE_TRANSCRIPT_SHA256);
	if ((pqcp_evidence_session_record(
		     &session, PQCP_EVIDENCE_EVENT_DEVICE_EVIDENCE, ret) != 0) ||
	    (ret != 0)) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}

	if (pqcp_evidence_session_end(&session) != 0) {
		printk("PROJECT EXECUTION FAILED\n");
		return 1;
	}

	printk("PROJECT EXECUTION SUCCESSFUL\n");
	return 0;
}
