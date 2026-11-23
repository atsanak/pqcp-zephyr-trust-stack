/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Fleet deployment policy appraisal
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_FLEET_POLICY_H_
#define PQCP_ZEPHYR_DEPLOYMENT_FLEET_POLICY_H_

#include <stdbool.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_fleet_consensus.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_DEPLOYMENT_FLEET_POLICY_SCHEMA_VERSION 1U
#define PQCP_DEPLOYMENT_FLEET_POLICY_DIGEST_HEX_CHARS 64U

enum pqcp_deployment_fleet_policy_profile {
	PQCP_DEPLOYMENT_FLEET_POLICY_PROTOTYPE = 0,
	PQCP_DEPLOYMENT_FLEET_POLICY_PAPER,
	PQCP_DEPLOYMENT_FLEET_POLICY_PRODUCT,
	PQCP_DEPLOYMENT_FLEET_POLICY_PARTNER,
	PQCP_DEPLOYMENT_FLEET_POLICY_HARDWARE,
};

enum pqcp_deployment_fleet_policy_status {
	PQCP_DEPLOYMENT_FLEET_POLICY_FAIL = 0,
	PQCP_DEPLOYMENT_FLEET_POLICY_WARN,
	PQCP_DEPLOYMENT_FLEET_POLICY_PASS,
};

#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_INVALID_INPUT (1U << 0)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_CONSENSUS_FAIL (1U << 1)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_DEVICE_COUNT (1U << 2)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_CANDIDATE_QUORUM (1U << 3)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_PROFILE_QUORUM (1U << 4)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_BOARD_QUORUM (1U << 5)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_SIGNATURE_COVERAGE (1U << 6)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_PRODUCTION_COVERAGE (1U << 7)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_SCORE_FLOOR (1U << 8)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_OUTLIERS (1U << 9)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_PASSPORT_FAILURES (1U << 10)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_AUDIT_FAILURES (1U << 11)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_REPLAY_FAILURES (1U << 12)
#define PQCP_DEPLOYMENT_FLEET_POLICY_BLOCK_KNOWN_MASK ((1U << 13) - 1U)

#define PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_CONSENSUS_WARN (1U << 0)
#define PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_LOW_QUORUM (1U << 1)
#define PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_UNSIGNED (1U << 2)
#define PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_NON_PRODUCTION (1U << 3)
#define PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_LOW_SCORE (1U << 4)
#define PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_OUTLIERS (1U << 5)
#define PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_FAILURE_HISTORY (1U << 6)
#define PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_HETEROGENEOUS_BOARD (1U << 7)
#define PQCP_DEPLOYMENT_FLEET_POLICY_WARNING_KNOWN_MASK ((1U << 8) - 1U)

#define PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_ADD_DEVICES (1U << 0)
#define PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_REPLAY_FAILED_DEVICE (1U << 1)
#define PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_REAUDIT_DEVICE (1U << 2)
#define PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_SIGN_PASSPORTS (1U << 3)
#define PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_PROMOTE_PRODUCTION (1U << 4)
#define PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_REPEAT_BENCHMARKS (1U << 5)
#define PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_RESOLVE_CANDIDATE_DRIFT (1U << 6)
#define PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_RESOLVE_PROFILE_DRIFT (1U << 7)
#define PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_RESOLVE_BOARD_DRIFT (1U << 8)
#define PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_INVESTIGATE_OUTLIERS (1U << 9)
#define PQCP_DEPLOYMENT_FLEET_POLICY_ACTION_KNOWN_MASK ((1U << 10) - 1U)

struct pqcp_deployment_fleet_policy {
	enum pqcp_deployment_fleet_policy_profile profile;
	uint32_t min_devices;
	uint32_t min_candidate_quorum_percent;
	uint32_t min_profile_quorum_percent;
	uint32_t min_board_quorum_percent;
	uint32_t min_signature_percent;
	uint32_t min_production_percent;
	uint32_t min_average_score;
	uint32_t max_outlier_percent;
	uint32_t max_passport_failures;
	uint32_t max_audit_failures;
	uint32_t max_replay_failures;
	bool require_consensus_pass;
	bool require_no_passport_failures;
	bool require_no_audit_failures;
	bool require_no_replay_failures;
	bool quorum_floor_blocks;
	bool signature_floor_blocks;
	bool production_floor_blocks;
	bool score_floor_blocks;
	bool outlier_floor_blocks;
};

struct pqcp_deployment_fleet_policy_result {
	uint32_t schema_version;
	enum pqcp_deployment_fleet_policy_profile profile;
	enum pqcp_deployment_fleet_policy_status status;
	uint32_t blocker_mask;
	uint32_t warning_mask;
	uint32_t action_mask;
	uint32_t readiness_score;
	uint32_t reviewer_risk_score;
	uint32_t evidence_grade;
	uint32_t device_count;
	uint32_t accepted_count;
	uint32_t signature_percent;
	uint32_t production_percent;
	uint32_t candidate_quorum_percent;
	uint32_t profile_quorum_percent;
	uint32_t board_quorum_percent;
	uint32_t outlier_percent;
	uint32_t average_score;
	bool consensus_digest_bound;
	char candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char board[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	enum pqcp_deployment_release_gate_profile deployment_profile;
	char consensus_digest_hex[
		PQCP_DEPLOYMENT_FLEET_CONSENSUS_DIGEST_HEX_CHARS + 1U];
	char policy_digest_hex[
		PQCP_DEPLOYMENT_FLEET_POLICY_DIGEST_HEX_CHARS + 1U];
};

const char *pqcp_deployment_fleet_policy_profile_str(
	enum pqcp_deployment_fleet_policy_profile profile);

const char *pqcp_deployment_fleet_policy_status_str(
	enum pqcp_deployment_fleet_policy_status status);

int pqcp_deployment_fleet_policy_default(
	enum pqcp_deployment_fleet_policy_profile profile,
	struct pqcp_deployment_fleet_policy *policy);

int pqcp_deployment_fleet_policy_evaluate(
	const struct pqcp_deployment_fleet_consensus_report *consensus,
	const struct pqcp_deployment_fleet_policy *policy,
	struct pqcp_deployment_fleet_policy_result *result);

int pqcp_deployment_fleet_policy_emit(
	const struct pqcp_deployment_fleet_policy_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_FLEET_POLICY_H_ */
