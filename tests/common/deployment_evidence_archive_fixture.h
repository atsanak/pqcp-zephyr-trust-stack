/*
 * SPDX-License-Identifier: MIT
 */

#ifndef PQCP_TEST_DEPLOYMENT_EVIDENCE_ARCHIVE_FIXTURE_H_
#define PQCP_TEST_DEPLOYMENT_EVIDENCE_ARCHIVE_FIXTURE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_archive.h>
#include <pqcp_zephyr/deployment_fleet_policy.h>

struct pqcp_archive_test_fixture {
	struct pqcp_capability_descriptor capability;
	struct pqcp_deployment_evidence_seal seal;
	struct pqcp_deployment_evidence_seal_replay_result seal_replay;
	struct pqcp_deployment_evidence_seal_audit_report seal_audit;
	struct pqcp_deployment_assurance_passport_policy passport_policy;
	struct pqcp_deployment_assurance_passport passport;
	struct pqcp_deployment_assurance_passport_replay_result passport_replay;
};

int pqcp_archive_test_build_passport(
	struct pqcp_archive_test_fixture *fixture,
	const char *board,
	const char *top_candidate,
	const char *nonce,
	bool production_allowed);

void pqcp_archive_test_fill_capsule_replay(
	struct pqcp_deployment_evidence_capsule_replay_result *result,
	const char *board,
	const char *top_candidate,
	const char *nonce,
	const char *passport_digest,
	const char *capsule_digest,
	uint32_t score,
	bool signed_verified,
	bool production_allowed);

void pqcp_archive_test_fill_journal_replay(
	struct pqcp_deployment_evidence_journal_replay_result *result,
	const char *device_id,
	const char *board,
	const char *top_candidate,
	const char *root_digest,
	const char *capsule_digest,
	uint32_t entries,
	uint32_t score,
	bool signed_verified,
	bool production_allowed);

void pqcp_archive_test_fill_journal_audit(
	struct pqcp_deployment_evidence_journal_audit_report *report,
	const char *device_id,
	const char *board,
	const char *first_root,
	const char *last_root,
	const char *audit_digest,
	uint32_t snapshots,
	uint32_t entries,
	uint32_t score,
	enum pqcp_deployment_evidence_journal_audit_status status);

void pqcp_archive_test_increment_digest(
	char digest[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U],
	uint32_t increment);

#endif /* PQCP_TEST_DEPLOYMENT_EVIDENCE_ARCHIVE_FIXTURE_H_ */
