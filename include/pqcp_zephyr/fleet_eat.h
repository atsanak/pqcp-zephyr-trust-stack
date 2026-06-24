/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * PQCP EAT/CWT profile and RATS appraisal types.
 */

#ifndef PQCP_ZEPHYR_FLEET_EAT_H_
#define PQCP_ZEPHYR_FLEET_EAT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/fleet_cose.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_EAT_ABI_VERSION 1U
#define PQCP_FLEET_EAT_PROFILE_URI \
	"urn:pqcp:fleet:eat-profile:1"
#define PQCP_FLEET_EAT_CONTENT_TYPE \
	"application/eat+cwt"
#define PQCP_FLEET_EAT_RESULT_CONTENT_TYPE \
	"application/pqcp-attestation-result+cwt"
#define PQCP_FLEET_EAT_NONCE_MIN_BYTES 8U
#define PQCP_FLEET_EAT_NONCE_MAX_BYTES 64U
#define PQCP_FLEET_EAT_UEID_MIN_BYTES 7U
#define PQCP_FLEET_EAT_UEID_MAX_BYTES 33U
#define PQCP_FLEET_EAT_MAX_TEXT_BYTES 64U
#define PQCP_FLEET_EAT_MAX_MEASUREMENTS 16U
#define PQCP_FLEET_EAT_MAX_ADVICE 8U
#define PQCP_FLEET_EAT_MAX_PRIVATE_CLAIMS 16U
#define PQCP_FLEET_EAT_DIGEST_BYTES 32U

#define PQCP_FLEET_CWT_CLAIM_ISSUER 1
#define PQCP_FLEET_CWT_CLAIM_SUBJECT 2
#define PQCP_FLEET_CWT_CLAIM_AUDIENCE 3
#define PQCP_FLEET_CWT_CLAIM_EXPIRATION 4
#define PQCP_FLEET_CWT_CLAIM_NOT_BEFORE 5
#define PQCP_FLEET_CWT_CLAIM_ISSUED_AT 6
#define PQCP_FLEET_CWT_CLAIM_TOKEN_ID 7
#define PQCP_FLEET_EAT_CLAIM_NONCE 10
#define PQCP_FLEET_EAT_CLAIM_UEID 256
#define PQCP_FLEET_EAT_CLAIM_SUEIDS 257
#define PQCP_FLEET_EAT_CLAIM_OEM_ID 258
#define PQCP_FLEET_EAT_CLAIM_HARDWARE_MODEL 259
#define PQCP_FLEET_EAT_CLAIM_HARDWARE_VERSION 260
#define PQCP_FLEET_EAT_CLAIM_UPTIME 261
#define PQCP_FLEET_EAT_CLAIM_OEM_BOOT 262
#define PQCP_FLEET_EAT_CLAIM_DEBUG_STATUS 263
#define PQCP_FLEET_EAT_CLAIM_LOCATION 264
#define PQCP_FLEET_EAT_CLAIM_PROFILE 265
#define PQCP_FLEET_EAT_CLAIM_SUBMODULES 266
#define PQCP_FLEET_EAT_CLAIM_BOOT_COUNT 267
#define PQCP_FLEET_EAT_CLAIM_BOOT_SEED 268
#define PQCP_FLEET_EAT_CLAIM_DLOAS 269
#define PQCP_FLEET_EAT_CLAIM_SOFTWARE_NAME 270
#define PQCP_FLEET_EAT_CLAIM_SOFTWARE_VERSION 271
#define PQCP_FLEET_EAT_CLAIM_MANIFESTS 272
#define PQCP_FLEET_EAT_CLAIM_MEASUREMENTS 273
#define PQCP_FLEET_EAT_CLAIM_MEASUREMENT_RESULTS 274
#define PQCP_FLEET_EAT_CLAIM_INTENDED_USE 275

#define PQCP_FLEET_EAT_PRIVATE_BASE (-70000)
#define PQCP_FLEET_EAT_CLAIM_ROLE \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 1)
#define PQCP_FLEET_EAT_CLAIM_POLICY_EPOCH \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 2)
#define PQCP_FLEET_EAT_CLAIM_REVOCATION_EPOCH \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 3)
#define PQCP_FLEET_EAT_CLAIM_CREDENTIAL_EPOCH \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 4)
#define PQCP_FLEET_EAT_CLAIM_RUNTIME_STATE \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 5)
#define PQCP_FLEET_EAT_CLAIM_RISK_SCORE \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 6)
#define PQCP_FLEET_EAT_CLAIM_CAPABILITIES \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 7)
#define PQCP_FLEET_EAT_CLAIM_FIRMWARE_DIGEST \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 8)
#define PQCP_FLEET_EAT_CLAIM_POLICY_DIGEST \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 9)
#define PQCP_FLEET_EAT_CLAIM_AUDIT_ROOT \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 10)
#define PQCP_FLEET_EAT_CLAIM_CHANNEL_BINDING \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 11)
#define PQCP_FLEET_EAT_CLAIM_MIGRATION_STATE \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 12)
#define PQCP_FLEET_EAT_CLAIM_UPDATE_STATE \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 13)
#define PQCP_FLEET_EAT_CLAIM_RESULT \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 14)
#define PQCP_FLEET_EAT_CLAIM_RESULT_REASON \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 15)
#define PQCP_FLEET_EAT_CLAIM_EVIDENCE_DIGEST \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 16)
#define PQCP_FLEET_EAT_CLAIM_REFERENCE_SET \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 17)
#define PQCP_FLEET_EAT_CLAIM_ADVICE \
	(PQCP_FLEET_EAT_PRIVATE_BASE - 18)

enum pqcp_fleet_eat_role {
	PQCP_FLEET_EAT_ROLE_NONE = 0,
	PQCP_FLEET_EAT_ROLE_EVIDENCE = 1,
	PQCP_FLEET_EAT_ROLE_ATTESTATION_RESULT = 2,
};

enum pqcp_fleet_eat_debug_status {
	PQCP_FLEET_EAT_DEBUG_ENABLED = 0,
	PQCP_FLEET_EAT_DEBUG_DISABLED = 1,
	PQCP_FLEET_EAT_DEBUG_DISABLED_SINCE_BOOT = 2,
	PQCP_FLEET_EAT_DEBUG_DISABLED_PERMANENTLY = 3,
	PQCP_FLEET_EAT_DEBUG_DISABLED_FULLY_AND_PERMANENTLY = 4,
};

enum pqcp_fleet_eat_measurement_result {
	PQCP_FLEET_EAT_MEASUREMENT_SUCCESS = 1,
	PQCP_FLEET_EAT_MEASUREMENT_FAILURE = 2,
	PQCP_FLEET_EAT_MEASUREMENT_NOT_RUN = 3,
	PQCP_FLEET_EAT_MEASUREMENT_ABSENT = 4,
};

enum pqcp_fleet_eat_appraisal {
	PQCP_FLEET_EAT_APPRAISAL_INDETERMINATE = 0,
	PQCP_FLEET_EAT_APPRAISAL_TRUSTED = 1,
	PQCP_FLEET_EAT_APPRAISAL_UNTRUSTED = 2,
	PQCP_FLEET_EAT_APPRAISAL_STALE = 3,
	PQCP_FLEET_EAT_APPRAISAL_REVOKED = 4,
	PQCP_FLEET_EAT_APPRAISAL_QUARANTINE = 5,
};

enum pqcp_fleet_eat_advice {
	PQCP_FLEET_EAT_ADVICE_NONE = 0,
	PQCP_FLEET_EAT_ADVICE_ALLOW = 1,
	PQCP_FLEET_EAT_ADVICE_LIMIT = 2,
	PQCP_FLEET_EAT_ADVICE_REMEDIATE = 3,
	PQCP_FLEET_EAT_ADVICE_ISOLATE = 4,
	PQCP_FLEET_EAT_ADVICE_LOCKDOWN = 5,
	PQCP_FLEET_EAT_ADVICE_REENROLL = 6,
};

enum pqcp_fleet_eat_runtime_state {
	PQCP_FLEET_EAT_RUNTIME_UNKNOWN = 0,
	PQCP_FLEET_EAT_RUNTIME_FACTORY,
	PQCP_FLEET_EAT_RUNTIME_ENROLLING,
	PQCP_FLEET_EAT_RUNTIME_OPERATIONAL,
	PQCP_FLEET_EAT_RUNTIME_MIGRATING,
	PQCP_FLEET_EAT_RUNTIME_RECOVERING,
	PQCP_FLEET_EAT_RUNTIME_REVOKED,
	PQCP_FLEET_EAT_RUNTIME_LOCKDOWN,
	PQCP_FLEET_EAT_RUNTIME_DECOMMISSIONED,
};

enum pqcp_fleet_eat_private_type {
	PQCP_FLEET_EAT_PRIVATE_UINT = 1,
	PQCP_FLEET_EAT_PRIVATE_INT,
	PQCP_FLEET_EAT_PRIVATE_BOOL,
	PQCP_FLEET_EAT_PRIVATE_BYTES,
	PQCP_FLEET_EAT_PRIVATE_TEXT,
};

struct pqcp_fleet_eat_measurement {
	char system[PQCP_FLEET_EAT_MAX_TEXT_BYTES];
	char identifier[PQCP_FLEET_EAT_MAX_TEXT_BYTES];
	enum pqcp_fleet_eat_measurement_result result;
	uint8_t digest[PQCP_FLEET_EAT_DIGEST_BYTES];
	size_t digest_length;
};

struct pqcp_fleet_eat_private_claim {
	int64_t label;
	enum pqcp_fleet_eat_private_type type;
	union {
		uint64_t unsigned_value;
		int64_t integer_value;
		bool boolean_value;
		struct pqcp_fleet_const_bytes bytes;
		const char *text;
	} value;
	size_t text_length;
};

struct pqcp_fleet_eat_claims {
	enum pqcp_fleet_eat_role role;
	uint8_t nonce[PQCP_FLEET_EAT_NONCE_MAX_BYTES];
	size_t nonce_length;
	uint8_t ueid[PQCP_FLEET_EAT_UEID_MAX_BYTES];
	size_t ueid_length;
	char issuer[PQCP_FLEET_EAT_MAX_TEXT_BYTES];
	char subject[PQCP_FLEET_EAT_MAX_TEXT_BYTES];
	char audience[PQCP_FLEET_EAT_MAX_TEXT_BYTES];
	char profile[PQCP_FLEET_COSE_MAX_PROFILE_BYTES];
	char software_name[PQCP_FLEET_EAT_MAX_TEXT_BYTES];
	char software_version[PQCP_FLEET_EAT_MAX_TEXT_BYTES];
	char hardware_version[PQCP_FLEET_EAT_MAX_TEXT_BYTES];
	uint8_t hardware_model[PQCP_FLEET_EAT_DIGEST_BYTES];
	size_t hardware_model_length;
	uint32_t oem_id;
	uint64_t issued_at;
	uint64_t expiration;
	uint64_t not_before;
	uint64_t uptime_seconds;
	uint64_t boot_count;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t credential_epoch;
	uint64_t capabilities;
	uint64_t reference_set;
	uint32_t risk_score;
	enum pqcp_fleet_eat_debug_status debug_status;
	enum pqcp_fleet_eat_runtime_state runtime_state;
	enum pqcp_fleet_eat_appraisal appraisal;
	uint32_t result_reason;
	bool oem_boot;
	bool issued_at_present;
	bool expiration_present;
	bool not_before_present;
	bool uptime_present;
	bool boot_count_present;
	bool policy_epoch_present;
	bool revocation_epoch_present;
	bool credential_epoch_present;
	bool capabilities_present;
	bool reference_set_present;
	bool risk_score_present;
	bool debug_status_present;
	bool runtime_state_present;
	bool appraisal_present;
	bool result_reason_present;
	uint8_t token_id[32];
	size_t token_id_length;
	uint8_t firmware_digest[PQCP_FLEET_EAT_DIGEST_BYTES];
	size_t firmware_digest_length;
	uint8_t policy_digest[PQCP_FLEET_EAT_DIGEST_BYTES];
	size_t policy_digest_length;
	uint8_t audit_root[PQCP_FLEET_EAT_DIGEST_BYTES];
	size_t audit_root_length;
	uint8_t channel_binding[PQCP_FLEET_EAT_DIGEST_BYTES];
	size_t channel_binding_length;
	uint8_t evidence_digest[PQCP_FLEET_EAT_DIGEST_BYTES];
	size_t evidence_digest_length;
	struct pqcp_fleet_eat_measurement
		measurements[PQCP_FLEET_EAT_MAX_MEASUREMENTS];
	size_t measurement_count;
	enum pqcp_fleet_eat_advice advice[PQCP_FLEET_EAT_MAX_ADVICE];
	size_t advice_count;
	struct pqcp_fleet_eat_private_claim
		private_claims[PQCP_FLEET_EAT_MAX_PRIVATE_CLAIMS];
	size_t private_claim_count;
};

struct pqcp_fleet_eat_freshness {
	uint64_t now;
	uint64_t maximum_age;
	uint64_t maximum_future_skew;
	const uint8_t *expected_nonce;
	size_t expected_nonce_length;
	bool require_nonce;
	bool require_expiration;
};

struct pqcp_fleet_eat_appraisal_policy {
	uint32_t maximum_risk_score;
	uint64_t minimum_policy_epoch;
	uint64_t minimum_revocation_epoch;
	uint64_t required_capabilities;
	enum pqcp_fleet_eat_debug_status maximum_debug_status;
	bool require_oem_boot;
	bool require_firmware_digest;
	bool require_policy_digest;
	bool require_channel_binding;
	bool reject_unknown_measurements;
	bool reject_failed_measurements;
};

struct pqcp_fleet_eat_appraisal_result {
	enum pqcp_fleet_eat_appraisal appraisal;
	uint32_t reason_mask;
	uint32_t accepted_measurements;
	uint32_t failed_measurements;
	uint32_t missing_measurements;
	enum pqcp_fleet_eat_advice advice[PQCP_FLEET_EAT_MAX_ADVICE];
	size_t advice_count;
};

int pqcp_fleet_eat_claims_validate(
	const struct pqcp_fleet_eat_claims *claims);
int pqcp_fleet_eat_claims_encode(
	const struct pqcp_fleet_eat_claims *claims,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_fleet_eat_claims_decode(
	const uint8_t *encoded,
	size_t encoded_length,
	struct pqcp_fleet_eat_claims *claims);
int pqcp_fleet_eat_token_sign(
	const struct pqcp_fleet_eat_claims *claims,
	const uint8_t *key_id,
	size_t key_id_length,
	const struct pqcp_fleet_cose_crypto *crypto,
	uint8_t *workspace,
	size_t workspace_capacity,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_fleet_eat_token_verify(
	const uint8_t *token,
	size_t token_length,
	const struct pqcp_fleet_cose_crypto *crypto,
	const struct pqcp_fleet_eat_freshness *freshness,
	uint8_t *workspace,
	size_t workspace_capacity,
	struct pqcp_fleet_eat_claims *claims);
int pqcp_fleet_eat_freshness_check(
	const struct pqcp_fleet_eat_claims *claims,
	const struct pqcp_fleet_eat_freshness *freshness);
int pqcp_fleet_eat_appraise_evidence(
	const struct pqcp_fleet_eat_claims *evidence,
	const struct pqcp_fleet_eat_appraisal_policy *policy,
	struct pqcp_fleet_eat_appraisal_result *result);
int pqcp_fleet_eat_make_result(
	const struct pqcp_fleet_eat_claims *evidence,
	const struct pqcp_fleet_eat_appraisal_result *appraisal,
	const uint8_t evidence_digest[PQCP_FLEET_EAT_DIGEST_BYTES],
	const char *verifier_id,
	const char *audience,
	uint64_t issued_at,
	uint64_t expiration,
	struct pqcp_fleet_eat_claims *result_claims);
int pqcp_fleet_eat_result_authorize(
	const struct pqcp_fleet_eat_claims *result_claims,
	const struct pqcp_fleet_eat_appraisal_policy *relying_policy,
	struct pqcp_fleet_eat_appraisal_result *result);
int pqcp_fleet_eat_claims_digest(
	const struct pqcp_fleet_eat_claims *claims,
	const struct pqcp_fleet_cose_crypto *crypto,
	uint8_t output[PQCP_FLEET_EAT_DIGEST_BYTES]);

const char *pqcp_fleet_eat_role_string(
	enum pqcp_fleet_eat_role role);
const char *pqcp_fleet_eat_appraisal_string(
	enum pqcp_fleet_eat_appraisal appraisal);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_EAT_H_ */
