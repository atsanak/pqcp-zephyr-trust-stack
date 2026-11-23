/*
 * SPDX-License-Identifier: MIT
 *
 * PQCP Zephyr Trust Stack - Firmware deployment evidence capsule
 *
 * Stability: experimental evidence API. A capsule is a canonical binary,
 * allocation-free transport container for one assurance passport, its replay
 * result, and an optional ML-DSA signature record.
 */

#ifndef PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_CAPSULE_H_
#define PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_CAPSULE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/deployment_assurance_passport_replay.h>
#include <pqcp_zephyr/deployment_evidence_codec.h>
#include <pqcp_zephyr/deployment_passport_signature.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_SCHEMA_VERSION 1U
#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAGIC UINT32_C(0x43515050)
#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES 32U
#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES 8192U
#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_RECORDS 16U
#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS 64U

#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_SIGNED          (1U << 0)
#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_REPLAY_PASSED   (1U << 1)
#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PRODUCTION      (1U << 2)
#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PASSPORT_PASS   (1U << 3)
#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_BOOT_POST_GATED (1U << 4)
#define PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_KNOWN_MASK \
	(PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_SIGNED | \
	 PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_REPLAY_PASSED | \
	 PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PRODUCTION | \
	 PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PASSPORT_PASS | \
	 PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_BOOT_POST_GATED)

enum pqcp_deployment_evidence_capsule_record_type {
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_CORE = 1,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_IDENTITY = 2,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_DIGESTS = 3,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_REPLAY = 4,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_SIGNATURE_META = 5,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PUBLIC_KEY = 6,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_SIGNATURE = 7,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_DIGEST = 0xffff,
};

enum pqcp_deployment_evidence_capsule_status {
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FAIL = 0,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_WARN,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_PASS,
};

enum pqcp_deployment_evidence_capsule_error {
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_NONE = 0,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_INVALID_ARGUMENT,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_PASSPORT,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_REPLAY,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_SIGNATURE,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BUFFER_TOO_SMALL,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_CODEC,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_RECORD_LIMIT,
	PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_DIGEST,
};

struct pqcp_deployment_evidence_capsule {
	uint32_t schema_version;
	enum pqcp_deployment_evidence_capsule_status status;
	enum pqcp_deployment_evidence_capsule_error first_error;
	uint32_t flags;
	uint32_t record_count;
	uint32_t byte_count;
	uint32_t passport_score;
	enum pqcp_deployment_assurance_passport_status passport_status;
	enum pqcp_deployment_release_gate_profile profile;
	bool replay_passed;
	bool signature_present;
	bool signature_verified;
	bool production_allowed;
	char board[PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS];
	char top_candidate_id[PQCP_DEPLOYMENT_ID_MAX_CHARS];
	char nonce_hex[PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS + 1U];
	char passport_digest_hex[
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS + 1U];
	char capsule_digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS + 1U];
};

const char *pqcp_deployment_evidence_capsule_status_str(
	enum pqcp_deployment_evidence_capsule_status status);

const char *pqcp_deployment_evidence_capsule_error_str(
	enum pqcp_deployment_evidence_capsule_error error);

size_t pqcp_deployment_evidence_capsule_required_bytes(
	bool include_signature);

int pqcp_deployment_evidence_capsule_build(
	const struct pqcp_deployment_assurance_passport *passport,
	const struct pqcp_deployment_assurance_passport_replay_result *replay,
	const struct pqcp_deployment_passport_signature *signature,
	uint8_t *buffer,
	size_t capacity,
	struct pqcp_deployment_evidence_capsule *capsule);

int pqcp_deployment_evidence_capsule_emit(
	const struct pqcp_deployment_evidence_capsule *capsule);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_DEPLOYMENT_EVIDENCE_CAPSULE_H_ */
