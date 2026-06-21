/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Canonical CBOR protocol for PQC device enrollment and fleet control.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_PROTOCOL_H_
#define PQCP_ZEPHYR_FLEET_PROTOCOL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/runtime_key_store.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_SCHEMA_VERSION 1U
#define PQCP_FLEET_PROTOCOL_VERSION 1U
#define PQCP_FLEET_ID_MAX_CHARS 48U
#define PQCP_FLEET_PRODUCT_MAX_CHARS 32U
#define PQCP_FLEET_VERSION_MAX_CHARS 24U
#define PQCP_FLEET_PROFILE_MAX_CHARS 32U
#define PQCP_FLEET_NONCE_BYTES 32U
#define PQCP_FLEET_DIGEST_BYTES 32U
#define PQCP_FLEET_MAX_REVOCATIONS 8U
#define PQCP_FLEET_MESSAGE_MAX_BYTES 8192U
#define PQCP_FLEET_MLDSA_LEVEL 65U
#define PQCP_FLEET_PUBLIC_KEY_BYTES PQCP_MLDSA_65_PK_SIZE
#define PQCP_FLEET_SIGNATURE_BYTES PQCP_MLDSA_65_SIG_SIZE
#define PQCP_FLEET_SIGNATURE_CONTEXT "PQCP-FLEET-CBOR-V1"
#define PQCP_FLEET_SIGNATURE_CONTEXT_BYTES 18U

#define PQCP_FLEET_MLKEM_512 (1U << 0)
#define PQCP_FLEET_MLKEM_768 (1U << 1)
#define PQCP_FLEET_MLKEM_1024 (1U << 2)
#define PQCP_FLEET_MLDSA_44 (1U << 0)
#define PQCP_FLEET_MLDSA_65 (1U << 1)
#define PQCP_FLEET_MLDSA_87 (1U << 2)

enum pqcp_fleet_message_type {
	PQCP_FLEET_MESSAGE_NONE = 0,
	PQCP_FLEET_MESSAGE_ENROLLMENT_REQUEST,
	PQCP_FLEET_MESSAGE_OWNERSHIP_VOUCHER,
	PQCP_FLEET_MESSAGE_OPERATIONAL_CREDENTIAL,
	PQCP_FLEET_MESSAGE_POLICY_BUNDLE,
	PQCP_FLEET_MESSAGE_REVOCATION_UPDATE,
	PQCP_FLEET_MESSAGE_UPDATE_MANIFEST,
	PQCP_FLEET_MESSAGE_ROTATION_REQUEST,
	PQCP_FLEET_MESSAGE_ROTATION_AUTHORIZATION,
	PQCP_FLEET_MESSAGE_COMMAND_RESULT,
	PQCP_FLEET_MESSAGE_TYPE_COUNT,
};

enum pqcp_fleet_enrollment_stage {
	PQCP_FLEET_ENROLLMENT_FACTORY = 1,
	PQCP_FLEET_ENROLLMENT_OPERATIONAL_KEY,
	PQCP_FLEET_ENROLLMENT_RECOVERY,
};

enum pqcp_fleet_capability {
	PQCP_FLEET_CAP_APPLICATION = (1U << 0),
	PQCP_FLEET_CAP_POLICY_UPDATE = (1U << 1),
	PQCP_FLEET_CAP_KEY_ROTATION = (1U << 2),
	PQCP_FLEET_CAP_FIRMWARE_UPDATE = (1U << 3),
	PQCP_FLEET_CAP_PROFILE_MIGRATION = (1U << 4),
	PQCP_FLEET_CAP_RECOVERY = (1U << 5),
	PQCP_FLEET_CAP_EMERGENCY_DOWNGRADE = (1U << 6),
	PQCP_FLEET_CAP_DECOMMISSION = (1U << 7),
};

enum pqcp_fleet_policy_flag {
	PQCP_FLEET_POLICY_HYBRID_REQUIRED = (1U << 0),
	PQCP_FLEET_POLICY_FORBID_DOWNGRADE = (1U << 1),
	PQCP_FLEET_POLICY_RECOVERY_ONLY = (1U << 2),
	PQCP_FLEET_POLICY_LOCKDOWN = (1U << 3),
};

enum pqcp_fleet_revocation_kind {
	PQCP_FLEET_REVOKE_CREDENTIAL = 1,
	PQCP_FLEET_REVOKE_DEVICE,
	PQCP_FLEET_REVOKE_DOMAIN,
};

enum pqcp_fleet_update_flag {
	PQCP_FLEET_UPDATE_REQUIRE_DRAIN = (1U << 0),
	PQCP_FLEET_UPDATE_REQUIRE_REBOOT = (1U << 1),
	PQCP_FLEET_UPDATE_ALLOW_RECOVERY = (1U << 2),
};

enum pqcp_fleet_command_status {
	PQCP_FLEET_COMMAND_ACCEPTED = 0,
	PQCP_FLEET_COMMAND_REJECTED,
	PQCP_FLEET_COMMAND_APPLIED,
	PQCP_FLEET_COMMAND_FAILED,
};

struct pqcp_fleet_signer {
	void *context;
	int (*sign)(
		void *context,
		const uint8_t *message,
		size_t message_length,
		const uint8_t *signature_context,
		size_t signature_context_length,
		uint8_t *signature,
		size_t signature_capacity,
		size_t *signature_length);
	struct pqcp_runtime_key_store *runtime_key_store;
	struct pqcp_runtime_key_handle runtime_key;
};

struct pqcp_fleet_envelope {
	uint32_t schema_version;
	uint32_t protocol_version;
	enum pqcp_fleet_message_type type;
	uint64_t message_id;
	uint64_t sequence;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint8_t nonce[PQCP_FLEET_NONCE_BYTES];
	char device_id[PQCP_FLEET_ID_MAX_CHARS];
	char domain_id[PQCP_FLEET_ID_MAX_CHARS];
};

struct pqcp_fleet_enrollment_request {
	struct pqcp_fleet_envelope envelope;
	enum pqcp_fleet_enrollment_stage stage;
	uint64_t boot_counter;
	uint64_t enrollment_counter;
	uint32_t supported_mlkem_mask;
	uint32_t supported_mldsa_mask;
	uint32_t requested_capabilities;
	char firmware_version[PQCP_FLEET_VERSION_MAX_CHARS];
	char product_class[PQCP_FLEET_PRODUCT_MAX_CHARS];
	uint8_t factory_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES];
	uint8_t factory_fingerprint[PQCP_FLEET_DIGEST_BYTES];
	uint8_t hardware_id_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t operational_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES];
	bool operational_key_present;
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES];
};

struct pqcp_fleet_ownership_voucher {
	struct pqcp_fleet_envelope envelope;
	uint8_t factory_fingerprint[PQCP_FLEET_DIGEST_BYTES];
	uint8_t operational_key_fingerprint[PQCP_FLEET_DIGEST_BYTES];
	uint8_t registrar_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES];
	uint32_t granted_capabilities;
	char product_class[PQCP_FLEET_PRODUCT_MAX_CHARS];
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES];
};

struct pqcp_fleet_credential {
	struct pqcp_fleet_envelope envelope;
	char credential_id[PQCP_FLEET_ID_MAX_CHARS];
	uint8_t subject_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES];
	uint32_t allowed_mlkem_mask;
	uint32_t allowed_mldsa_mask;
	uint32_t capabilities;
	uint64_t valid_from_ms;
	uint64_t valid_until_ms;
	uint64_t issuance_epoch;
	char product_class[PQCP_FLEET_PRODUCT_MAX_CHARS];
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES];
};

struct pqcp_fleet_policy_bundle {
	struct pqcp_fleet_envelope envelope;
	uint32_t allowed_mlkem_mask;
	uint32_t allowed_mldsa_mask;
	uint32_t preferred_mlkem_level;
	uint32_t preferred_mldsa_level;
	uint32_t minimum_security_level;
	uint32_t required_capabilities;
	uint32_t flags;
	uint32_t maximum_sessions;
	uint32_t maximum_jobs;
	uint32_t canary_percent;
	uint64_t credential_lifetime_ms;
	uint64_t rotation_window_ms;
	uint64_t rekey_after_bytes;
	uint64_t rekey_after_ms;
	char preferred_profile[PQCP_FLEET_PROFILE_MAX_CHARS];
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES];
};

struct pqcp_fleet_revocation_entry {
	enum pqcp_fleet_revocation_kind kind;
	char subject_id[PQCP_FLEET_ID_MAX_CHARS];
	uint64_t effective_at_ms;
	uint32_t reason;
};

struct pqcp_fleet_revocation_update {
	struct pqcp_fleet_envelope envelope;
	uint64_t previous_epoch;
	uint64_t next_refresh_ms;
	uint64_t offline_grace_ms;
	uint32_t entry_count;
	struct pqcp_fleet_revocation_entry
		entries[PQCP_FLEET_MAX_REVOCATIONS];
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES];
};

struct pqcp_fleet_update_manifest {
	struct pqcp_fleet_envelope envelope;
	char component_id[PQCP_FLEET_ID_MAX_CHARS];
	char product_class[PQCP_FLEET_PRODUCT_MAX_CHARS];
	uint64_t version;
	uint64_t minimum_current_version;
	uint64_t image_size;
	uint32_t required_capabilities;
	uint32_t flags;
	uint8_t image_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES];
};

struct pqcp_fleet_rotation_request {
	struct pqcp_fleet_envelope envelope;
	char current_credential_id[PQCP_FLEET_ID_MAX_CHARS];
	uint8_t current_key_fingerprint[PQCP_FLEET_DIGEST_BYTES];
	uint8_t new_operational_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES];
	uint64_t requested_overlap_ms;
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES];
};

struct pqcp_fleet_rotation_authorization {
	struct pqcp_fleet_envelope envelope;
	char authorization_id[PQCP_FLEET_ID_MAX_CHARS];
	char replacement_credential_id[PQCP_FLEET_ID_MAX_CHARS];
	uint8_t old_key_fingerprint[PQCP_FLEET_DIGEST_BYTES];
	uint8_t new_key_fingerprint[PQCP_FLEET_DIGEST_BYTES];
	uint64_t valid_from_ms;
	uint64_t valid_until_ms;
	uint64_t overlap_until_ms;
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES];
};

struct pqcp_fleet_command_result {
	struct pqcp_fleet_envelope envelope;
	uint64_t command_message_id;
	uint64_t applied_policy_epoch;
	uint64_t applied_revocation_epoch;
	uint32_t device_state;
	enum pqcp_fleet_command_status status;
	int32_t result;
	uint32_t reason;
	uint8_t signature[PQCP_FLEET_SIGNATURE_BYTES];
};

int pqcp_fleet_envelope_validate(
	const struct pqcp_fleet_envelope *envelope,
	enum pqcp_fleet_message_type type,
	uint64_t now_ms);
int pqcp_fleet_public_key_fingerprint(
	const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	uint8_t fingerprint[PQCP_FLEET_DIGEST_BYTES]);

#define PQCP_FLEET_DECLARE_MESSAGE_API(prefix, type) \
	int pqcp_fleet_##prefix##_sign( \
		struct type *message, \
		const struct pqcp_fleet_signer *signer, \
		uint64_t now_ms); \
	int pqcp_fleet_##prefix##_verify( \
		const struct type *message, \
		const uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES], \
		uint64_t now_ms); \
	int pqcp_fleet_##prefix##_encode( \
		const struct type *message, \
		uint8_t *output, size_t capacity, size_t *length); \
	int pqcp_fleet_##prefix##_decode( \
		const uint8_t *input, size_t length, \
		struct type *message)

PQCP_FLEET_DECLARE_MESSAGE_API(
	enrollment_request, pqcp_fleet_enrollment_request);
PQCP_FLEET_DECLARE_MESSAGE_API(
	voucher, pqcp_fleet_ownership_voucher);
PQCP_FLEET_DECLARE_MESSAGE_API(
	credential, pqcp_fleet_credential);
PQCP_FLEET_DECLARE_MESSAGE_API(
	policy, pqcp_fleet_policy_bundle);
PQCP_FLEET_DECLARE_MESSAGE_API(
	revocation, pqcp_fleet_revocation_update);
PQCP_FLEET_DECLARE_MESSAGE_API(
	update_manifest, pqcp_fleet_update_manifest);
PQCP_FLEET_DECLARE_MESSAGE_API(
	rotation_request, pqcp_fleet_rotation_request);
PQCP_FLEET_DECLARE_MESSAGE_API(
	rotation_authorization,
	pqcp_fleet_rotation_authorization);
PQCP_FLEET_DECLARE_MESSAGE_API(
	command_result, pqcp_fleet_command_result);

#undef PQCP_FLEET_DECLARE_MESSAGE_API

int pqcp_fleet_message_type_peek(
	const uint8_t *input,
	size_t length,
	enum pqcp_fleet_message_type *type);
const char *pqcp_fleet_message_type_str(
	enum pqcp_fleet_message_type type);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_PROTOCOL_H_ */
