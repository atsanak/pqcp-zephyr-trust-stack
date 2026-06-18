/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP Zephyr Trust Stack - Append-only deployment evidence journal
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_JOURNAL_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_JOURNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_capsule_replay.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_SCHEMA_VERSION 1U
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES 16U
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DEVICE_ID_MAX_CHARS 48U
#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS 64U

enum pqcp_deployment_evidence_journal_status {
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_EMPTY = 0,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_OPEN,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FINALIZED,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_FAILED,
};

enum pqcp_deployment_evidence_journal_error {
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BAD_DEVICE_ID,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BAD_CAPSULE,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_FULL,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_FINALIZED,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_SEQUENCE,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_BOOT_COUNTER,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_TIME_ORDER,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_DUPLICATE,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_ERROR_DIGEST,
};

struct pqcp_deployment_evidence_journal_entry {
	uint32_t schema_version;
	uint32_t sequence;
	uint64_t boot_counter;
	uint64_t capture_time_ms;
	enum pqcp_deployment_assurance_passport_status passport_status;
	enum pqcp_deployment_release_gate_profile profile;
	uint32_t passport_score;
	uint32_t capsule_bytes;
	uint32_t capsule_records;
	bool capsule_replayed;
	bool signature_present;
	bool signature_verified;
	bool production_allowed;
	char device_id[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DEVICE_ID_MAX_CHARS];
	char board[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	char passport_digest_hex[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U];
	char capsule_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS + 1U];
	char previous_entry_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	char entry_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_deployment_evidence_journal {
	uint32_t schema_version;
	enum pqcp_deployment_evidence_journal_status status;
	enum pqcp_deployment_evidence_journal_error first_error;
	uint32_t entry_count;
	uint32_t pass_count;
	uint32_t warn_count;
	uint32_t fail_count;
	uint32_t signed_count;
	uint32_t production_count;
	uint32_t distinct_capsule_count;
	uint64_t first_boot_counter;
	uint64_t last_boot_counter;
	uint64_t first_capture_time_ms;
	uint64_t last_capture_time_ms;
	bool monotonic_boot_counters;
	bool monotonic_capture_times;
	bool unique_capsules;
	bool stable_device_id;
	bool stable_board;
	char device_id[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DEVICE_ID_MAX_CHARS];
	char board[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	char first_entry_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	char last_entry_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	char journal_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	struct pqcp_deployment_evidence_journal_entry
		entries[PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_MAX_ENTRIES];
};

const char *pqcp_deployment_evidence_journal_status_str(
	enum pqcp_deployment_evidence_journal_status status);

const char *pqcp_deployment_evidence_journal_error_str(
	enum pqcp_deployment_evidence_journal_error error);

int pqcp_deployment_evidence_journal_init(
	struct pqcp_deployment_evidence_journal *journal,
	const char *device_id);

int pqcp_deployment_evidence_journal_append(
	struct pqcp_deployment_evidence_journal *journal,
	const struct pqcp_deployment_evidence_capsule_replay_result *capsule,
	uint64_t boot_counter,
	uint64_t capture_time_ms);

int pqcp_deployment_evidence_journal_finalize(
	struct pqcp_deployment_evidence_journal *journal);

const struct pqcp_deployment_evidence_journal_entry *
pqcp_deployment_evidence_journal_entry_at(
	const struct pqcp_deployment_evidence_journal *journal,
	size_t index);

int pqcp_deployment_evidence_journal_emit(
	const struct pqcp_deployment_evidence_journal *journal);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_JOURNAL_H_ */
