/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment evidence journal replay
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_journal.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_SCHEMA_VERSION 1U

enum pqcp_deployment_evidence_journal_replay_error {
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BAD_SCHEMA,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_NOT_FINALIZED,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_EMPTY,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ENTRY_SCHEMA,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_SEQUENCE,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BOOT_COUNTER,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_TIME_ORDER,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_DEVICE_DRIFT,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_BOARD_DRIFT,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_DUPLICATE_CAPSULE,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_PREVIOUS_DIGEST,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ENTRY_DIGEST,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_SUMMARY,
	PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_ERROR_ROOT_DIGEST,
};

struct pqcp_deployment_evidence_journal_replay_result {
	uint32_t schema_version;
	bool passed;
	enum pqcp_deployment_evidence_journal_replay_error first_error;
	uint32_t first_error_entry;
	uint32_t entries_checked;
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
	enum pqcp_deployment_assurance_passport_status latest_passport_status;
	enum pqcp_deployment_release_gate_profile latest_profile;
	uint32_t latest_passport_score;
	bool latest_signature_verified;
	bool latest_production_allowed;
	bool sequence_valid;
	bool boot_counters_valid;
	bool capture_times_valid;
	bool device_stable;
	bool board_stable;
	bool capsules_unique;
	bool entry_chain_valid;
	bool summary_valid;
	bool root_digest_valid;
	char device_id[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DEVICE_ID_MAX_CHARS];
	char board[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	char latest_top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char latest_capsule_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS + 1U];
	char first_entry_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	char last_entry_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	char computed_journal_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
};

const char *pqcp_deployment_evidence_journal_replay_error_str(
	enum pqcp_deployment_evidence_journal_replay_error error);

int pqcp_deployment_evidence_journal_replay_verify(
	const struct pqcp_deployment_evidence_journal *journal,
	struct pqcp_deployment_evidence_journal_replay_result *result);

int pqcp_deployment_evidence_journal_replay_emit(
	const struct pqcp_deployment_evidence_journal_replay_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_JOURNAL_REPLAY_H_ */
