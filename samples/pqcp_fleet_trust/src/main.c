/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Durable device and gateway demonstration of the PQC fleet trust fabric.
 */

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>
#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/fleet_enrollment.h>
#include <pqcp_zephyr/fleet_registrar.h>

#define RUNTIME_KEYS 8U
#define RUNTIME_WORKSPACES 1U
#define RUNTIME_WORKSPACE_BYTES 49152U
#define RUNTIME_JOBS 4U
#define RUNTIME_SESSIONS 2U
#define RUNTIME_PROFILES 4U
#define RUNTIME_AUDIT 16U
#define RUNTIME_IDENTITIES 6U
#define RUNTIME_QUOTAS 2U

struct runtime_storage {
	struct pqcp_runtime_volatile_slot keys[RUNTIME_KEYS];
	struct pqcp_runtime_workspace_slot workspaces[RUNTIME_WORKSPACES];
	uint8_t workspace_bytes[
		RUNTIME_WORKSPACES * RUNTIME_WORKSPACE_BYTES];
	struct pqcp_runtime_queue_entry jobs[RUNTIME_JOBS];
	struct pqcp_runtime_session sessions[RUNTIME_SESSIONS];
	struct pqcp_runtime_profile_state profiles[RUNTIME_PROFILES];
	struct pqcp_runtime_audit_entry audit[RUNTIME_AUDIT];
	struct pqcp_runtime_identity identities[RUNTIME_IDENTITIES];
	struct pqcp_runtime_admission_quota quotas[RUNTIME_QUOTAS];
};

static struct runtime_storage device_storage;
static struct runtime_storage gateway_storage;
static struct pqcp_runtime_service device_runtime;
static struct pqcp_runtime_service gateway_runtime;
static struct pqcp_adaptive_control_plane device_adaptive;
static struct pqcp_adaptive_control_plane gateway_adaptive;
static struct pqcp_fleet_device_record registrar_records[2];
static struct pqcp_fleet_registrar registrar;
static struct pqcp_fleet_device device;
static struct pqcp_fleet_store fleet_store;
static struct pqcp_fleet_memory_store fleet_memory;
static uint8_t protocol_buffer[PQCP_FLEET_MESSAGE_MAX_BYTES];

static int initialize_runtime(
	struct pqcp_runtime_service *runtime,
	struct pqcp_adaptive_control_plane *adaptive,
	struct runtime_storage *storage,
	const char *device_id)
{
	const struct pqcp_runtime_service_storage descriptor = {
		.key_slots = storage->keys,
		.key_slot_count = ARRAY_SIZE(storage->keys),
		.workspace_slots = storage->workspaces,
		.workspace_bytes = storage->workspace_bytes,
		.workspace_slot_count = ARRAY_SIZE(storage->workspaces),
		.workspace_bytes_per_slot = RUNTIME_WORKSPACE_BYTES,
		.queue = storage->jobs,
		.queue_capacity = ARRAY_SIZE(storage->jobs),
		.sessions = storage->sessions,
		.session_capacity = ARRAY_SIZE(storage->sessions),
		.profile_states = storage->profiles,
		.profile_state_capacity = ARRAY_SIZE(storage->profiles),
		.audit_entries = storage->audit,
		.audit_capacity = ARRAY_SIZE(storage->audit),
		.identities = storage->identities,
		.identity_capacity = ARRAY_SIZE(storage->identities),
		.quotas = storage->quotas,
		.quota_capacity = ARRAY_SIZE(storage->quotas),
	};
	int ret;

	memset(storage, 0, sizeof(*storage));
	memset(runtime, 0, sizeof(*runtime));
	memset(adaptive, 0, sizeof(*adaptive));
	ret = pqcp_adaptive_control_init(
		adaptive, device_id, PQCP_ADAPTIVE_POLICY_GATEWAY,
		"hybrid768-65-runtime", 1000U);
	return ret == 0 ?
		pqcp_runtime_service_init(
			runtime, &descriptor, adaptive, 1000U) :
		ret;
}

static int enrollment_roundtrip(
	const struct pqcp_fleet_enrollment_request *input,
	struct pqcp_fleet_enrollment_request *output)
{
	size_t length = 0U;
	int ret = pqcp_fleet_enrollment_request_encode(
		input, protocol_buffer, sizeof(protocol_buffer), &length);

	return ret == 0 ?
		pqcp_fleet_enrollment_request_decode(
			protocol_buffer, length, output) :
		ret;
}

static void fill_bytes(uint8_t *output, size_t length, uint8_t seed)
{
	for (size_t index = 0U; index < length; ++index) {
		output[index] = (uint8_t)(seed + index);
	}
}

static int run_lifecycle(void)
{
	struct pqcp_runtime_identity *factory;
	struct pqcp_runtime_identity *signer;
	const uint32_t capabilities =
		PQCP_FLEET_CAP_APPLICATION |
		PQCP_FLEET_CAP_POLICY_UPDATE |
		PQCP_FLEET_CAP_KEY_ROTATION |
		PQCP_FLEET_CAP_FIRMWARE_UPDATE |
		PQCP_FLEET_CAP_PROFILE_MIGRATION |
		PQCP_FLEET_CAP_RECOVERY;
	const struct pqcp_fleet_registrar_config registrar_config = {
		.domain_id = "factory-domain",
		.signing_identity_id = "registrar-signer",
		.voucher_lifetime_ms = 300000U,
		.credential_lifetime_ms = 3600000U,
		.default_capabilities = capabilities,
		.allowed_mlkem_mask = PQCP_FLEET_MLKEM_768,
		.allowed_mldsa_mask = PQCP_FLEET_MLDSA_65,
	};
	static const struct pqcp_fleet_policy_bundle policy_template = {
		.allowed_mlkem_mask = PQCP_FLEET_MLKEM_768,
		.allowed_mldsa_mask = PQCP_FLEET_MLDSA_65,
		.preferred_mlkem_level = 768U,
		.preferred_mldsa_level = 65U,
		.minimum_security_level = 3U,
		.required_capabilities = PQCP_FLEET_CAP_APPLICATION,
		.flags = PQCP_FLEET_POLICY_HYBRID_REQUIRED |
			 PQCP_FLEET_POLICY_FORBID_DOWNGRADE,
		.maximum_sessions = 4U,
		.maximum_jobs = 8U,
		.canary_percent = 10U,
		.credential_lifetime_ms = 3600000U,
		.rotation_window_ms = 300000U,
		.rekey_after_bytes = 1024U * 1024U,
		.rekey_after_ms = 600000U,
		.preferred_profile = "hybrid768-65-runtime",
	};
	static struct pqcp_fleet_enrollment_request request;
	static struct pqcp_fleet_enrollment_request decoded_request;
	static struct pqcp_fleet_ownership_voucher voucher;
	static struct pqcp_fleet_credential credential;
	static struct pqcp_fleet_policy_bundle policy;
	static struct pqcp_fleet_rotation_request rotation_request;
	static struct pqcp_fleet_rotation_authorization
		rotation_authorization;
	static struct pqcp_fleet_credential replacement_credential;
	static struct pqcp_fleet_update_manifest update;
	static struct pqcp_fleet_update_decision update_decision;
	static struct pqcp_fleet_revocation_update revocation;
	static struct pqcp_channel_config channel_config;
	static uint8_t hardware_id[PQCP_FLEET_DIGEST_BYTES];
	static uint8_t enrollment_nonce[PQCP_FLEET_NONCE_BYTES];
	static uint8_t rotation_nonce[PQCP_FLEET_NONCE_BYTES];
	static uint8_t image_digest[PQCP_FLEET_DIGEST_BYTES];
	static uint8_t registrar_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES];
	uint64_t applied_policy_epoch = 0U;
	uint64_t applied_revocation_epoch = 0U;
	int ret;

	fill_bytes(hardware_id, sizeof(hardware_id), 0x10U);
	fill_bytes(enrollment_nonce, sizeof(enrollment_nonce), 0x30U);
	fill_bytes(rotation_nonce, sizeof(rotation_nonce), 0x50U);
	fill_bytes(image_digest, sizeof(image_digest), 0xa0U);

	ret = initialize_runtime(
		&device_runtime, &device_adaptive,
		&device_storage, "edge-device-001");
	if (ret == 0) {
		ret = initialize_runtime(
			&gateway_runtime, &gateway_adaptive,
			&gateway_storage, "fleet-gateway");
	}
	if (ret == 0) {
		ret = pqcp_runtime_identity_create_local(
			&device_runtime.identities, "factory-identity",
			PQCP_FLEET_MLDSA_LEVEL, 1000U, 86400000U,
			&factory);
	}
	if (ret == 0) {
		ret = pqcp_runtime_identity_create_local(
			&gateway_runtime.identities, "registrar-signer",
			PQCP_FLEET_MLDSA_LEVEL, 1000U, 86400000U,
			&signer);
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_init(
			&registrar, &registrar_config, &gateway_runtime,
			registrar_records, ARRAY_SIZE(registrar_records));
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_public_key(
			&registrar, registrar_public_key);
	}
	if (ret == 0) {
		ret = pqcp_fleet_memory_store_init(
			&fleet_store, &fleet_memory);
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_init(
			&device, &device_runtime, &fleet_store,
			"edge-device-001", "1.0.0",
			"industrial-gateway", 1U, hardware_id,
			registrar_public_key, &factory->local_key, true);
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_admit_factory(
			&registrar, "edge-device-001",
			"industrial-gateway", factory->peer_public_key,
			hardware_id, capabilities);
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_build_enrollment_request(
			&device, "factory-domain", enrollment_nonce,
			1U, 2000U, 62000U,
			PQCP_FLEET_MLKEM_768, PQCP_FLEET_MLDSA_65,
			capabilities, &request);
	}
	if (ret == 0) {
		ret = enrollment_roundtrip(&request, &decoded_request);
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_issue_voucher(
			&registrar, &decoded_request, 2100U, &voucher);
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_issue_credential(
			&registrar, &decoded_request, 2200U, &credential);
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_install_ownership(
			&device, &voucher, &credential, 2300U);
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_issue_policy(
			&registrar, "edge-device-001",
			&policy_template, 2400U, &policy);
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_apply_policy(
			&device, &policy, 2500U);
		if (ret == 0) {
			applied_policy_epoch =
				device.record.policy.envelope.policy_epoch;
		}
	}
	memset(&channel_config, 0, sizeof(channel_config));
	if (ret == 0) {
		ret = pqcp_fleet_device_configure_channel(
			&device, &channel_config);
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_begin_rotation(
			&device, rotation_nonce, 2U, 2600U, 62600U,
			1000U, &rotation_request);
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_authorize_rotation(
			&registrar, &rotation_request, 2700U,
			&rotation_authorization,
			&replacement_credential);
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_complete_rotation(
			&device, &rotation_authorization,
			&replacement_credential, 2800U);
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_commit_rotation(
			&registrar, "edge-device-001");
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_tick(&device, 3800U);
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_issue_update(
			&registrar, "edge-device-001", "application",
			2U, 1U, 65536U, image_digest,
			PQCP_FLEET_UPDATE_REQUIRE_DRAIN |
				PQCP_FLEET_UPDATE_REQUIRE_REBOOT,
			3900U, &update);
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_authorize_update(
			&device, &update, 4000U, &update_decision);
	}
	if (ret == 0 && !update_decision.authorized) {
		ret = -EACCES;
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_complete_update(
			&device, true, 4100U);
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_audit(&device, 4150U);
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_issue_revocation(
			&registrar, "edge-device-001",
			PQCP_FLEET_REVOKE_CREDENTIAL,
			device.record.credential.credential_id,
			1U, 4200U, &revocation);
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_apply_revocation(
			&device, &revocation, 4300U);
		if (ret == 0) {
			applied_revocation_epoch =
				device.record.revocation_epoch;
		}
	}
	if (ret == 0 &&
	    device.record.state != PQCP_FLEET_DEVICE_REVOKED) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_decommission(
			&registrar, "edge-device-001");
	}
	if (ret == 0) {
		ret = pqcp_fleet_device_decommission(&device, 4400U);
	}
	if (ret == 0 &&
	    (device.record.state !=
		     PQCP_FLEET_DEVICE_DECOMMISSIONED ||
	     device.record.current_firmware_version != 2U ||
	     channel_config.local_identity.family !=
		     PQCP_RUNTIME_KEY_MLDSA_KEYPAIR)) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_fleet_registrar_audit(
			&registrar, 4500U);
	}
	if (ret == 0) {
		printk("PQCP_FLEET_TRUST device=edge-device-001 state=decommissioned policy_epoch=%llu revocation_epoch=%llu firmware_version=%llu rotation=retired update=committed\n",
		       (unsigned long long)applied_policy_epoch,
		       (unsigned long long)applied_revocation_epoch,
		       (unsigned long long)
			       device.record.current_firmware_version);
	}
	return ret;
}

int main(void)
{
	int ret = psa_crypto_init();

	if (ret == PSA_SUCCESS) {
		ret = run_lifecycle();
	}
	printk("PQCP_FLEET_TRUST_RESULT status=%s result=%d\n",
	       ret == 0 ? "PASS" : "FAIL", ret);
	return ret;
}
