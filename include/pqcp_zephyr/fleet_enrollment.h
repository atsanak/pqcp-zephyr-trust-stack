/*
 * SPDX-License-Identifier: MIT
 *
 * Device-side enrollment and fleet trust lifecycle.
 */

#ifndef PQCP_ZEPHYR_FLEET_ENROLLMENT_H_
#define PQCP_ZEPHYR_FLEET_ENROLLMENT_H_

#include <pqcp_zephyr/fleet_store.h>
#include <pqcp_zephyr/protected_channel.h>
#include <pqcp_zephyr/runtime_migration.h>
#include <pqcp_zephyr/runtime_service.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pqcp_fleet_runtime_bindings {
	struct pqcp_runtime_service *service;
	struct pqcp_runtime_migration *migration;
};

struct pqcp_fleet_runtime_signer_context {
	struct pqcp_runtime_key_store *key_store;
	struct pqcp_runtime_key_handle key;
};

struct pqcp_fleet_device {
	struct pqcp_runtime_service *runtime;
	struct pqcp_fleet_store *store;
	struct pqcp_fleet_store_record record;
	char device_id[PQCP_FLEET_ID_MAX_CHARS];
	char firmware_version[PQCP_FLEET_VERSION_MAX_CHARS];
	char product_class[PQCP_FLEET_PRODUCT_MAX_CHARS];
	uint8_t hardware_id_digest[PQCP_FLEET_DIGEST_BYTES];
	bool development_volatile_identity;
	bool initialized;
};

struct pqcp_fleet_update_decision {
	uint64_t version;
	uint64_t image_size;
	uint32_t flags;
	uint8_t image_digest[PQCP_FLEET_DIGEST_BYTES];
	bool authorized;
};

int pqcp_fleet_runtime_signer_init(
	struct pqcp_fleet_signer *signer,
	struct pqcp_fleet_runtime_signer_context *context,
	struct pqcp_runtime_key_store *key_store,
	const struct pqcp_runtime_key_handle *key);
int pqcp_fleet_device_init(
	struct pqcp_fleet_device *device,
	struct pqcp_runtime_service *runtime,
	struct pqcp_fleet_store *store,
	const char *device_id,
	const char *firmware_version,
	const char *product_class,
	uint64_t current_firmware_version,
	const uint8_t hardware_id_digest[PQCP_FLEET_DIGEST_BYTES],
	const uint8_t registrar_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	const struct pqcp_runtime_key_handle *factory_key,
	bool development_volatile_identity);
int pqcp_fleet_device_build_enrollment_request(
	struct pqcp_fleet_device *device,
	const char *target_domain_id,
	const uint8_t nonce[PQCP_FLEET_NONCE_BYTES],
	uint64_t message_id,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint32_t supported_mlkem_mask,
	uint32_t supported_mldsa_mask,
	uint32_t requested_capabilities,
	struct pqcp_fleet_enrollment_request *request);
int pqcp_fleet_device_install_ownership(
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_ownership_voucher *voucher,
	const struct pqcp_fleet_credential *credential,
	uint64_t now_ms);
int pqcp_fleet_device_apply_policy(
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_policy_bundle *policy,
	uint64_t now_ms);
int pqcp_fleet_device_apply_revocation(
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_revocation_update *update,
	uint64_t now_ms);
int pqcp_fleet_device_authorize_update(
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_update_manifest *manifest,
	uint64_t now_ms,
	struct pqcp_fleet_update_decision *decision);
int pqcp_fleet_device_complete_update(
	struct pqcp_fleet_device *device,
	bool installed,
	uint64_t now_ms);
int pqcp_fleet_device_begin_rotation(
	struct pqcp_fleet_device *device,
	const uint8_t nonce[PQCP_FLEET_NONCE_BYTES],
	uint64_t message_id,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	uint64_t requested_overlap_ms,
	struct pqcp_fleet_rotation_request *request);
int pqcp_fleet_device_complete_rotation(
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_rotation_authorization *authorization,
	const struct pqcp_fleet_credential *replacement_credential,
	uint64_t now_ms);
int pqcp_fleet_device_configure_channel(
	struct pqcp_fleet_device *device,
	struct pqcp_channel_config *config);
int pqcp_fleet_device_tick(
	struct pqcp_fleet_device *device,
	uint64_t now_ms);
int pqcp_fleet_device_decommission(
	struct pqcp_fleet_device *device,
	uint64_t now_ms);
int pqcp_fleet_device_audit(
	const struct pqcp_fleet_device *device,
	uint64_t now_ms);

int pqcp_fleet_channel_send(
	struct pqcp_channel *channel,
	const uint8_t *message,
	size_t message_length,
	uint32_t message_id);
int pqcp_fleet_channel_receive(
	struct pqcp_channel *channel,
	uint8_t *message,
	size_t message_capacity,
	size_t *message_length,
	uint32_t *message_id);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_ENROLLMENT_H_ */
