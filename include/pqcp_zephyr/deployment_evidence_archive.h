/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - End-to-end deployment evidence archive
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_ARCHIVE_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_ARCHIVE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_journal_replay.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_SCHEMA_VERSION 1U
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_DIGEST_HEX_CHARS 64U

enum pqcp_deployment_evidence_archive_status {
	PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_FAIL = 0,
	PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARN,
	PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_PASS,
};

#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_INVALID_INPUT (1U << 0)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_CAPSULE_BUILD (1U << 1)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_CAPSULE_REPLAY (1U << 2)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_INIT (1U << 3)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_APPEND (1U << 4)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_FINALIZE (1U << 5)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_JOURNAL_REPLAY (1U << 6)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_BINDING (1U << 7)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_DIGEST (1U << 8)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_ERROR_KNOWN_MASK ((1U << 9) - 1U)

#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARNING_PASSPORT_NOT_PASS (1U << 0)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARNING_UNSIGNED (1U << 1)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARNING_NON_PRODUCTION (1U << 2)
#define PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_WARNING_KNOWN_MASK ((1U << 3) - 1U)

struct pqcp_deployment_evidence_archive_result {
	uint32_t schema_version;
	enum pqcp_deployment_evidence_archive_status status;
	uint32_t error_mask;
	uint32_t warning_mask;
	uint32_t capsule_bytes;
	uint32_t capsule_records;
	uint32_t journal_entries;
	uint64_t boot_counter;
	uint64_t capture_time_ms;
	bool capsule_built;
	bool capsule_replayed;
	bool journal_appended;
	bool journal_finalized;
	bool journal_replayed;
	bool capsule_digest_bound;
	bool passport_digest_bound;
	bool signature_verified;
	bool production_allowed;
	enum pqcp_deployment_assurance_passport_status passport_status;
	enum pqcp_deployment_release_gate_profile profile;
	uint32_t passport_score;
	char device_id[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DEVICE_ID_MAX_CHARS];
	char board[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char passport_digest_hex[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U];
	char capsule_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS + 1U];
	char journal_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	char archive_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_ARCHIVE_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_deployment_evidence_archive_workspace {
	struct pqcp_deployment_evidence_capsule capsule;
	struct pqcp_deployment_evidence_capsule_replay_workspace capsule_workspace;
	struct pqcp_deployment_evidence_capsule_replay_result capsule_replay;
	struct pqcp_deployment_evidence_journal finalized_snapshot;
	struct pqcp_deployment_evidence_journal_replay_result journal_replay;
};

const char *pqcp_deployment_evidence_archive_status_str(
	enum pqcp_deployment_evidence_archive_status status);

int pqcp_deployment_evidence_archive_capture(
	const struct pqcp_deployment_assurance_passport *passport,
	const struct pqcp_deployment_assurance_passport_replay_result *passport_replay,
	const struct pqcp_deployment_passport_signature *signature,
	const char *device_id,
	uint64_t boot_counter,
	uint64_t capture_time_ms,
	uint8_t *capsule_buffer,
	size_t capsule_capacity,
	struct pqcp_deployment_evidence_journal *journal,
	struct pqcp_deployment_evidence_archive_workspace *workspace,
	struct pqcp_deployment_evidence_archive_result *result);

int pqcp_deployment_evidence_archive_emit(
	const struct pqcp_deployment_evidence_archive_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_ARCHIVE_H_ */
