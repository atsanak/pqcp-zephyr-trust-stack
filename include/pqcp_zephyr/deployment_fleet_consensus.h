/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Fleet deployment evidence consensus
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_FLEET_CONSENSUS_H_
#define PQCP_ZEPHYR_DEPLOYMENT_FLEET_CONSENSUS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_journal_audit.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_SCHEMA_VERSION 1U
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_DEVICES 16U
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_GROUPS 8U
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_DIGEST_HEX_CHARS 64U

#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_INVALID_INPUT (1U << 0)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_REPLAY_FAILURE (1U << 1)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_AUDIT_FAILURE (1U << 2)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_IDENTITY_MISMATCH (1U << 3)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_DUPLICATE_DEVICE (1U << 4)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_QUORUM (1U << 5)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_PROFILE_DRIFT (1U << 6)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_BOARD_DRIFT (1U << 7)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_CANDIDATE_DRIFT (1U << 8)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_SIGNATURE_COVERAGE (1U << 9)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_PRODUCTION_COVERAGE (1U << 10)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_SCORE_FLOOR (1U << 11)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_ERROR_KNOWN_MASK ((1U << 12) - 1U)

#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_AUDIT_WARN (1U << 0)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_PROFILE_DRIFT (1U << 1)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_BOARD_DRIFT (1U << 2)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_CANDIDATE_DRIFT (1U << 3)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_UNSIGNED (1U << 4)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_NON_PRODUCTION (1U << 5)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_LOW_SCORE (1U << 6)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_OUTLIERS (1U << 7)
#define PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARNING_KNOWN_MASK ((1U << 8) - 1U)

enum pqcp_deployment_fleet_consensus_status {
	PQCP_DEPLOYMENT_FLEET_CONSENSUS_FAIL = 0,
	PQCP_DEPLOYMENT_FLEET_CONSENSUS_WARN,
	PQCP_DEPLOYMENT_FLEET_CONSENSUS_PASS,
};

struct pqcp_deployment_fleet_consensus_policy {
	uint32_t min_devices;
	uint32_t min_quorum_percent;
	uint32_t min_signature_percent;
	uint32_t min_production_percent;
	uint32_t min_average_score;
	bool require_all_replays;
	bool require_all_audits;
	bool require_profile_consensus;
	bool require_board_consensus;
	bool require_candidate_consensus;
	bool signature_floor_blocks;
	bool production_floor_blocks;
	bool score_floor_blocks;
};

struct pqcp_deployment_fleet_member {
	uint32_t index;
	bool accepted;
	bool outlier;
	bool replay_passed;
	enum pqcp_deployment_evidence_journal_audit_status audit_status;
	enum pqcp_deployment_assurance_passport_status passport_status;
	enum pqcp_deployment_release_gate_profile profile;
	uint32_t latest_score;
	uint32_t journal_entries;
	uint32_t audit_snapshots;
	bool signature_verified;
	bool production_allowed;
	char device_id[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DEVICE_ID_MAX_CHARS];
	char board[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char journal_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_DIGEST_HEX_CHARS + 1U];
	char audit_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_JOURNAL_AUDIT_DIGEST_HEX_CHARS + 1U];
};

struct pqcp_deployment_fleet_group {
	char value[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	uint32_t member_count;
	uint32_t score_sum;
	uint32_t average_score;
};

struct pqcp_deployment_fleet_consensus_report {
	uint32_t schema_version;
	enum pqcp_deployment_fleet_consensus_status status;
	uint32_t error_mask;
	uint32_t warning_mask;
	uint32_t device_count;
	uint32_t accepted_count;
	uint32_t rejected_count;
	uint32_t outlier_count;
	uint32_t replay_pass_count;
	uint32_t audit_pass_count;
	uint32_t audit_warn_count;
	uint32_t audit_fail_count;
	uint32_t signature_count;
	uint32_t production_count;
	uint32_t passport_pass_count;
	uint32_t passport_warn_count;
	uint32_t passport_fail_count;
	uint32_t min_score;
	uint32_t max_score;
	uint32_t average_score;
	uint32_t candidate_quorum_percent;
	uint32_t board_quorum_percent;
	uint32_t profile_quorum_percent;
	uint32_t distinct_candidates;
	uint32_t distinct_boards;
	uint32_t distinct_profiles;
	enum pqcp_deployment_release_gate_profile consensus_profile;
	char consensus_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char consensus_board[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	char fleet_digest_hex[
		PQCP_DEPLOYMENT_FLEET_CONSENSUS_DIGEST_HEX_CHARS + 1U];
	struct pqcp_deployment_fleet_member
		members[PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_DEVICES];
	struct pqcp_deployment_fleet_group
		candidate_groups[PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_GROUPS];
	struct pqcp_deployment_fleet_group
		board_groups[PQCP_DEPLOYMENT_FLEET_CONSENSUS_MAX_GROUPS];
	uint32_t profile_counts[4];
};

const char *pqcp_deployment_fleet_consensus_status_str(
	enum pqcp_deployment_fleet_consensus_status status);

int pqcp_deployment_fleet_consensus_default_policy(
	struct pqcp_deployment_fleet_consensus_policy *policy);

int pqcp_deployment_fleet_consensus_run(
	const struct pqcp_deployment_evidence_journal_replay_result *journals,
	const struct pqcp_deployment_evidence_journal_audit_report *audits,
	size_t device_count,
	const struct pqcp_deployment_fleet_consensus_policy *policy,
	struct pqcp_deployment_fleet_consensus_report *report);

int pqcp_deployment_fleet_consensus_emit(
	const struct pqcp_deployment_fleet_consensus_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_FLEET_CONSENSUS_H_ */
