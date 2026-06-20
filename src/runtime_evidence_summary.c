/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Compact firmware-visible summary of executable runtime state.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/runtime_governance.h>

#include "runtime_internal.h"

static int summary_digest(
	struct pqcp_runtime_evidence_summary *summary)
{
	return pqcp_runtime_internal_sha256(
		(const uint8_t *)summary,
		offsetof(struct pqcp_runtime_evidence_summary,
			 summary_digest),
		summary->summary_digest);
}

int pqcp_runtime_evidence_summary_build(
	struct pqcp_runtime_controller *controller,
	const struct pqcp_runtime_identity_store *identities,
	struct pqcp_runtime_evidence_summary *summary)
{
	int ret;

	if (controller == NULL || identities == NULL ||
	    summary == NULL || !controller->initialized) {
		return -EINVAL;
	}
	memset(summary, 0, sizeof(*summary));
	summary->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	ret = pqcp_runtime_capability_current(
		&summary->capability);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_health_evaluate(
		controller, &summary->health);
	if (ret != 0 &&
	    summary->health.status !=
		    PQCP_RUNTIME_HEALTH_LOCKDOWN) {
		return ret;
	}
	summary->active_sessions =
		controller->sessions->active_count;
	summary->active_keys =
		controller->key_store->active_count;
	summary->active_identities =
		identities->active_count;
	summary->jobs_submitted =
		controller->executor->submitted_count;
	summary->jobs_completed =
		controller->executor->completed_count;
	summary->jobs_failed =
		controller->executor->failed_count;
	summary->audit_sequence =
		controller->audit->next_sequence - 1U;
	memcpy(summary->audit_root,
	       controller->audit->root_digest,
	       sizeof(summary->audit_root));
	return summary_digest(summary);
}

int pqcp_runtime_evidence_summary_verify(
	const struct pqcp_runtime_evidence_summary *summary)
{
	struct pqcp_runtime_evidence_summary copy;

	if (summary == NULL ||
	    summary->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    pqcp_runtime_capability_validate(
		    &summary->capability) != 0 ||
	    summary->jobs_completed +
		    summary->jobs_failed >
		    summary->jobs_submitted) {
		return -EINVAL;
	}
	copy = *summary;
	if (summary_digest(&copy) != 0 ||
	    memcmp(copy.summary_digest,
		   summary->summary_digest,
		   sizeof(copy.summary_digest)) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_runtime_evidence_summary_emit(
	const struct pqcp_runtime_evidence_summary *summary)
{
	char audit_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];
	char summary_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];
	int ret = pqcp_runtime_evidence_summary_verify(summary);

	if (ret != 0) {
		return ret;
	}
	(void)pqcp_runtime_internal_hex(
		summary->audit_root, sizeof(summary->audit_root),
		audit_hex, sizeof(audit_hex));
	(void)pqcp_runtime_internal_hex(
		summary->summary_digest,
		sizeof(summary->summary_digest),
		summary_hex, sizeof(summary_hex));
	printk("PQCP_RUNTIME_EVIDENCE schema=%u health=%u sessions=%u keys=%u identities=%u jobs_submitted=%llu jobs_completed=%llu jobs_failed=%llu audit_sequence=%llu audit_root=%s digest=%s\n",
	       summary->schema_version,
	       summary->health.status,
	       summary->active_sessions,
	       summary->active_keys,
	       summary->active_identities,
	       (unsigned long long)summary->jobs_submitted,
	       (unsigned long long)summary->jobs_completed,
	       (unsigned long long)summary->jobs_failed,
	       (unsigned long long)summary->audit_sequence,
	       audit_hex, summary_hex);
	return 0;
}
