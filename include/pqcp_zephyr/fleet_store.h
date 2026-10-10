/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Durable device trust state for the PQCP fleet protocol.
 */

#ifndef PQCP_ZEPHYR_FLEET_STORE_H_
#define PQCP_ZEPHYR_FLEET_STORE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/fleet_protocol.h>
#include <pqcp_zephyr/runtime_key_store.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_STORE_SCHEMA_VERSION 2U

enum pqcp_fleet_device_state {
	PQCP_FLEET_DEVICE_FACTORY = 0,
	PQCP_FLEET_DEVICE_ENROLLING,
	PQCP_FLEET_DEVICE_OWNED,
	PQCP_FLEET_DEVICE_OPERATIONAL,
	PQCP_FLEET_DEVICE_ROTATING,
	PQCP_FLEET_DEVICE_RECOVERY,
	PQCP_FLEET_DEVICE_REVOKED,
	PQCP_FLEET_DEVICE_DECOMMISSIONED,
};

struct pqcp_fleet_store_record {
	uint32_t schema_version;
	uint64_t commit_generation;
	enum pqcp_fleet_device_state state;
	struct pqcp_runtime_key_handle factory_key;
	struct pqcp_runtime_key_handle operational_key;
	struct pqcp_runtime_key_handle pending_operational_key;
	uint8_t factory_fingerprint[PQCP_FLEET_DIGEST_BYTES];
	uint8_t registrar_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES];
	struct pqcp_fleet_credential credential;
	struct pqcp_fleet_policy_bundle policy;
	uint64_t boot_counter;
	uint64_t enrollment_counter;
	uint64_t last_inbound_sequence;
	uint64_t last_outbound_sequence;
	uint64_t revocation_epoch;
	uint64_t revocation_refresh_due_ms;
	uint64_t offline_grace_ms;
	uint64_t rotation_overlap_until_ms;
	uint64_t current_firmware_version;
	uint64_t pending_enrollment_message_id;
	uint64_t pending_rotation_message_id;
	uint64_t pending_update_version;
	uint64_t pending_update_image_size;
	uint32_t granted_capabilities;
	uint32_t pending_update_flags;
	uint32_t pending_revocation_count;
	char product_class[PQCP_FLEET_PRODUCT_MAX_CHARS];
	struct pqcp_fleet_revocation_entry
		pending_revocations[PQCP_FLEET_MAX_REVOCATIONS];
	uint8_t pending_enrollment_nonce[PQCP_FLEET_NONCE_BYTES];
	uint8_t pending_rotation_nonce[PQCP_FLEET_NONCE_BYTES];
	uint8_t pending_update_digest[PQCP_FLEET_DIGEST_BYTES];
	bool factory_key_valid;
	bool operational_key_valid;
	bool pending_operational_key_valid;
	bool pending_update_valid;
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_store_backend {
	void *context;
	int (*read_slot)(
		void *context, size_t slot,
		struct pqcp_fleet_store_record *record);
	int (*write_slot)(
		void *context, size_t slot,
		const struct pqcp_fleet_store_record *record);
	int (*erase_slot)(void *context, size_t slot);
};

struct pqcp_fleet_store {
	struct pqcp_fleet_store_backend backend;
	size_t active_slot;
	uint64_t generation;
	bool initialized;
};

struct pqcp_fleet_memory_store {
	struct pqcp_fleet_store_record slots[2];
	bool valid[2];
};

int pqcp_fleet_store_record_verify(
	const struct pqcp_fleet_store_record *record);
int pqcp_fleet_store_init(
	struct pqcp_fleet_store *store,
	const struct pqcp_fleet_store_backend *backend);
int pqcp_fleet_store_load(
	struct pqcp_fleet_store *store,
	struct pqcp_fleet_store_record *record);
int pqcp_fleet_store_commit(
	struct pqcp_fleet_store *store,
	struct pqcp_fleet_store_record *record);
int pqcp_fleet_store_clear(struct pqcp_fleet_store *store);
int pqcp_fleet_memory_store_init(
	struct pqcp_fleet_store *store,
	struct pqcp_fleet_memory_store *memory);

#if defined(CONFIG_PQCP_FLEET_STORE_ITS)
struct pqcp_fleet_its_store {
	uint64_t slot_uid[2];
};

int pqcp_fleet_its_store_init(
	struct pqcp_fleet_store *store,
	struct pqcp_fleet_its_store *its,
	uint64_t first_uid);
#endif

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_STORE_H_ */
