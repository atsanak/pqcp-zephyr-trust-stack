/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Deployment evidence capsule replay
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_evidence_capsule.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_SCHEMA_VERSION 1U

enum pqcp_deployment_evidence_capsule_replay_error {
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_HEADER,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_SCHEMA,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_FLAGS,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_LENGTH,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_RECORD_ORDER,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DUPLICATE_RECORD,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MISSING_RECORD,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MALFORMED_RECORD,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DIGEST_MISMATCH,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_PASSPORT_REPLAY,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_SIGNATURE,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_FLAG_MISMATCH,
};

struct pqcp_deployment_evidence_capsule_replay_workspace {
	struct pqcp_deployment_assurance_passport passport;
	struct pqcp_deployment_assurance_passport_replay_result replay;
	struct pqcp_deployment_passport_signature signature;
};

struct pqcp_deployment_evidence_capsule_replay_result {
	uint32_t schema_version;
	bool passed;
	enum pqcp_deployment_evidence_capsule_replay_error first_error;
	enum pqcp_deployment_evidence_codec_error codec_error;
	uint32_t flags;
	uint32_t records_expected;
	uint32_t records_seen;
	uint32_t bytes_consumed;
	uint32_t record_mask;
	enum pqcp_deployment_assurance_passport_status passport_status;
	enum pqcp_deployment_release_gate_profile profile;
	uint32_t passport_score;
	bool passport_replayed;
	bool signature_present;
	bool signature_verified;
	bool digest_verified;
	bool production_allowed;
	char board[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	char passport_digest_hex[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U];
	char capsule_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS + 1U];
};

const char *pqcp_deployment_evidence_capsule_replay_error_str(
	enum pqcp_deployment_evidence_capsule_replay_error error);

int pqcp_deployment_evidence_capsule_replay_verify(
	const uint8_t *buffer,
	size_t length,
	struct pqcp_deployment_evidence_capsule_replay_workspace *workspace,
	struct pqcp_deployment_evidence_capsule_replay_result *result);

int pqcp_deployment_evidence_capsule_replay_emit(
	const struct pqcp_deployment_evidence_capsule_replay_result *result);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_H_ */
