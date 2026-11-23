/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free gateway registrar for PQC device fleets.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_FLEET_REGISTRAR_H_
#define PQCP_ZEPHYR_FLEET_REGISTRAR_H_

#include <pqcp_zephyr/fleet_protocol.h>
#include <pqcp_zephyr/runtime_service.h>

#ifdef __cplusplus
extern "C" {
#endif

enum pqcp_fleet_registrar_device_state {
	PQCP_FLEET_REGISTRAR_DEVICE_ADMITTED = 0,
	PQCP_FLEET_REGISTRAR_DEVICE_VOUCHERED,
	PQCP_FLEET_REGISTRAR_DEVICE_OPERATIONAL,
	PQCP_FLEET_REGISTRAR_DEVICE_ROTATING,
	PQCP_FLEET_REGISTRAR_DEVICE_SUSPENDED,
	PQCP_FLEET_REGISTRAR_DEVICE_REVOKED,
	PQCP_FLEET_REGISTRAR_DEVICE_DECOMMISSIONED,
};

struct pqcp_fleet_device_record {
	uint32_t schema_version;
	enum pqcp_fleet_registrar_device_state state;
	char device_id[PQCP_FLEET_ID_MAX_CHARS];
	char product_class[PQCP_FLEET_PRODUCT_MAX_CHARS];
	uint8_t factory_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES];
	uint8_t factory_fingerprint[PQCP_FLEET_DIGEST_BYTES];
	uint8_t hardware_id_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t operational_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES];
	uint8_t pending_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES];
	uint64_t last_sequence;
	uint64_t credential_epoch;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	uint32_t granted_capabilities;
	struct pqcp_fleet_credential active_credential;
	struct pqcp_fleet_credential pending_credential;
	bool operational_key_present;
	bool pending_key_present;
	bool pending_credential_present;
	bool occupied;
};

struct pqcp_fleet_registrar_config {
	char domain_id[PQCP_FLEET_ID_MAX_CHARS];
	char signing_identity_id[PQCP_RUNTIME_IDENTITY_MAX_ID_CHARS];
	uint64_t voucher_lifetime_ms;
	uint64_t credential_lifetime_ms;
	uint32_t default_capabilities;
	uint32_t allowed_mlkem_mask;
	uint32_t allowed_mldsa_mask;
};

struct pqcp_fleet_registrar {
	uint32_t schema_version;
	struct pqcp_fleet_registrar_config config;
	struct pqcp_runtime_service *runtime;
	struct pqcp_runtime_identity *signer;
	struct pqcp_fleet_device_record *records;
	size_t capacity;
	uint64_t next_message_id;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	struct k_mutex lock;
	bool initialized;
};

int pqcp_fleet_registrar_init(
	struct pqcp_fleet_registrar *registrar,
	const struct pqcp_fleet_registrar_config *config,
	struct pqcp_runtime_service *runtime,
	struct pqcp_fleet_device_record *records,
	size_t capacity);
int pqcp_fleet_registrar_public_key(
	const struct pqcp_fleet_registrar *registrar,
	uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES]);
int pqcp_fleet_registrar_admit_factory(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id,
	const char *product_class,
	const uint8_t factory_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	const uint8_t hardware_id_digest[PQCP_FLEET_DIGEST_BYTES],
	uint32_t capabilities);
int pqcp_fleet_registrar_issue_voucher(
	struct pqcp_fleet_registrar *registrar,
	const struct pqcp_fleet_enrollment_request *request,
	uint64_t now_ms,
	struct pqcp_fleet_ownership_voucher *voucher);
int pqcp_fleet_registrar_issue_credential(
	struct pqcp_fleet_registrar *registrar,
	const struct pqcp_fleet_enrollment_request *request,
	uint64_t now_ms,
	struct pqcp_fleet_credential *credential);
int pqcp_fleet_registrar_issue_policy(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id,
	const struct pqcp_fleet_policy_bundle *template_policy,
	uint64_t now_ms,
	struct pqcp_fleet_policy_bundle *policy);
int pqcp_fleet_registrar_issue_revocation(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id,
	enum pqcp_fleet_revocation_kind kind,
	const char *subject_id,
	uint32_t reason,
	uint64_t now_ms,
	struct pqcp_fleet_revocation_update *update);
int pqcp_fleet_registrar_issue_update(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id,
	const char *component_id,
	uint64_t version,
	uint64_t minimum_current_version,
	uint64_t image_size,
	const uint8_t image_digest[PQCP_FLEET_DIGEST_BYTES],
	uint32_t flags,
	uint64_t now_ms,
	struct pqcp_fleet_update_manifest *manifest);
int pqcp_fleet_registrar_authorize_rotation(
	struct pqcp_fleet_registrar *registrar,
	const struct pqcp_fleet_rotation_request *request,
	uint64_t now_ms,
	struct pqcp_fleet_rotation_authorization *authorization,
	struct pqcp_fleet_credential *replacement_credential);
int pqcp_fleet_registrar_commit_rotation(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id);
int pqcp_fleet_registrar_decommission(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id);
struct pqcp_fleet_device_record *pqcp_fleet_registrar_find(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id);
int pqcp_fleet_registrar_audit(
	struct pqcp_fleet_registrar *registrar,
	uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_REGISTRAR_H_ */
