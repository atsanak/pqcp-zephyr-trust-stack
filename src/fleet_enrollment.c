/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Device-side ownership, policy, rotation, update, and decommission lifecycle.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_enrollment.h>

#include "runtime_internal.h"

static int runtime_sign(
	void *context, const uint8_t *message, size_t message_length,
	const uint8_t *signature_context,
	size_t signature_context_length,
	uint8_t *signature, size_t signature_capacity,
	size_t *signature_length)
{
	struct pqcp_fleet_runtime_signer_context *signer = context;

	return pqcp_runtime_key_store_sign(
		signer->key_store, &signer->key,
		message, message_length, signature_context,
		signature_context_length, signature,
		signature_capacity, signature_length);
}

int pqcp_fleet_runtime_signer_init(
	struct pqcp_fleet_signer *signer,
	struct pqcp_fleet_runtime_signer_context *context,
	struct pqcp_runtime_key_store *key_store,
	const struct pqcp_runtime_key_handle *key)
{
	struct pqcp_runtime_key_metadata metadata;
	int ret;

	if (signer == NULL || context == NULL ||
	    key_store == NULL || key == NULL ||
	    key->family != PQCP_RUNTIME_KEY_MLDSA_KEYPAIR ||
	    key->level != PQCP_FLEET_MLDSA_LEVEL) {
		return -EINVAL;
	}
	ret = pqcp_runtime_key_store_metadata(
		key_store, key, &metadata);
	if (ret != 0 ||
	    (metadata.usage & PQCP_RUNTIME_USAGE_SIGN) == 0U) {
		return ret != 0 ? ret : -EACCES;
	}
	memset(signer, 0, sizeof(*signer));
	memset(context, 0, sizeof(*context));
	context->key_store = key_store;
	context->key = *key;
	signer->runtime_key_store = key_store;
	signer->runtime_key = *key;
	signer->context = context;
	signer->sign = runtime_sign;
	return 0;
}

static int generate_operational_key(
	struct pqcp_fleet_device *device,
	uint64_t now_ms,
	struct pqcp_runtime_key_handle *key)
{
	const struct pqcp_runtime_key_request request = {
		.family = PQCP_RUNTIME_KEY_MLDSA_KEYPAIR,
		.level = PQCP_FLEET_MLDSA_LEVEL,
		.usage = PQCP_RUNTIME_USAGE_SIGN |
			PQCP_RUNTIME_USAGE_VERIFY |
			PQCP_RUNTIME_USAGE_EXPORT_PUBLIC |
			PQCP_RUNTIME_USAGE_DESTROY,
		.now_ms = now_ms,
		.expires_at_ms = 0U,
		.owner = "fleet",
		.label = "operational-identity",
		.persistent = !device->development_volatile_identity,
		.exportable_public = true,
	};

	if (!device->development_volatile_identity &&
	    device->runtime->key_store.backend !=
		    PQCP_RUNTIME_KEY_BACKEND_PSA_PERSISTENT) {
		return -ENOTSUP;
	}
	return pqcp_runtime_key_store_generate(
		&device->runtime->key_store, &request, key);
}

static int export_key(
	struct pqcp_fleet_device *device,
	const struct pqcp_runtime_key_handle *key,
	uint8_t output[PQCP_FLEET_PUBLIC_KEY_BYTES])
{
	size_t length = 0U;
	int ret = pqcp_runtime_key_store_export_public(
		&device->runtime->key_store, key, output,
		PQCP_FLEET_PUBLIC_KEY_BYTES, &length);

	return ret == 0 && length == PQCP_FLEET_PUBLIC_KEY_BYTES ?
		0 : ret != 0 ? ret : -EBADMSG;
}

int pqcp_fleet_device_init(
	struct pqcp_fleet_device *device,
	struct pqcp_runtime_service *runtime,
	struct pqcp_fleet_store *store,
	const char *device_id, const char *firmware_version,
	const char *product_class,
	uint64_t current_firmware_version,
	const uint8_t hardware_id_digest[PQCP_FLEET_DIGEST_BYTES],
	const uint8_t registrar_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	const struct pqcp_runtime_key_handle *factory_key,
	bool development_volatile_identity)
{
	uint8_t factory_public[PQCP_FLEET_PUBLIC_KEY_BYTES];
	int ret;

	if (device == NULL || runtime == NULL || !runtime->initialized ||
	    store == NULL || !store->initialized ||
	    device_id == NULL || firmware_version == NULL ||
	    product_class == NULL ||
	    current_firmware_version == 0U ||
	    hardware_id_digest == NULL || factory_key == NULL ||
	    registrar_public_key == NULL ||
	    factory_key->family != PQCP_RUNTIME_KEY_MLDSA_KEYPAIR ||
	    factory_key->level != PQCP_FLEET_MLDSA_LEVEL) {
		return -EINVAL;
	}
	memset(device, 0, sizeof(*device));
	device->runtime = runtime;
	device->store = store;
	device->development_volatile_identity =
		development_volatile_identity;
	ret = pqcp_runtime_internal_copy_text(
		device->device_id, sizeof(device->device_id), device_id);
	if (ret == 0) ret = pqcp_runtime_internal_copy_text(
		device->firmware_version,
		sizeof(device->firmware_version), firmware_version);
	if (ret == 0) ret = pqcp_runtime_internal_copy_text(
		device->product_class,
		sizeof(device->product_class), product_class);
	if (ret != 0) return ret;
	memcpy(device->hardware_id_digest, hardware_id_digest,
	       sizeof(device->hardware_id_digest));
	ret = pqcp_fleet_store_load(store, &device->record);
	if (ret == -ENOENT) {
		memset(&device->record, 0, sizeof(device->record));
		device->record.schema_version =
			PQCP_FLEET_STORE_SCHEMA_VERSION;
		device->record.state = PQCP_FLEET_DEVICE_FACTORY;
		device->record.factory_key = *factory_key;
		device->record.factory_key_valid = true;
		memcpy(device->record.registrar_public_key,
		       registrar_public_key,
		       sizeof(device->record.registrar_public_key));
		device->record.boot_counter = 1U;
		device->record.current_firmware_version =
			current_firmware_version;
		ret = export_key(
			device, factory_key, factory_public);
		if (ret == 0) {
			ret = pqcp_fleet_public_key_fingerprint(
				factory_public,
				device->record.factory_fingerprint);
		}
		if (ret == 0) {
			ret = pqcp_fleet_store_commit(
				store, &device->record);
		}
	} else if (ret == 0) {
		if (memcmp(&device->record.factory_key, factory_key,
			   sizeof(*factory_key)) != 0 ||
		    memcmp(device->record.registrar_public_key,
			   registrar_public_key,
			   sizeof(device->record.registrar_public_key)) != 0) {
			return -EKEYREJECTED;
		}
		device->record.boot_counter++;
		if (current_firmware_version >
		    device->record.current_firmware_version) {
			device->record.current_firmware_version =
				current_firmware_version;
		}
		ret = pqcp_fleet_store_commit(store, &device->record);
	}
	pqcp_runtime_secure_zero(
		factory_public, sizeof(factory_public));
	if (ret == 0) device->initialized = true;
	return ret;
}

int pqcp_fleet_device_build_enrollment_request(
	struct pqcp_fleet_device *device,
	const char *target_domain_id,
	const uint8_t nonce[PQCP_FLEET_NONCE_BYTES],
	uint64_t message_id, uint64_t now_ms, uint64_t expires_at_ms,
	uint32_t supported_mlkem_mask,
	uint32_t supported_mldsa_mask,
	uint32_t requested_capabilities,
	struct pqcp_fleet_enrollment_request *request)
{
	struct pqcp_fleet_signer signer;
	struct pqcp_fleet_runtime_signer_context signer_context;
	uint8_t factory_public[PQCP_FLEET_PUBLIC_KEY_BYTES];
	int ret;

	if (device == NULL || !device->initialized ||
	    target_domain_id == NULL || nonce == NULL ||
	    request == NULL || message_id == 0U ||
	    expires_at_ms <= now_ms ||
	    supported_mlkem_mask == 0U ||
	    supported_mldsa_mask == 0U ||
	    requested_capabilities == 0U ||
	    !device->record.factory_key_valid ||
	    (device->record.state != PQCP_FLEET_DEVICE_FACTORY &&
	     device->record.state != PQCP_FLEET_DEVICE_ENROLLING)) {
		return -EINVAL;
	}
	if (!device->record.pending_operational_key_valid &&
	    !device->record.operational_key_valid) {
		ret = generate_operational_key(
			device, now_ms,
			&device->record.pending_operational_key);
		if (ret != 0) return ret;
		device->record.pending_operational_key_valid = true;
	}
	memset(request, 0, sizeof(*request));
	request->envelope.schema_version = PQCP_FLEET_SCHEMA_VERSION;
	request->envelope.protocol_version = PQCP_FLEET_PROTOCOL_VERSION;
	request->envelope.type =
		PQCP_FLEET_MESSAGE_ENROLLMENT_REQUEST;
	request->envelope.message_id = message_id;
	request->envelope.sequence =
		++device->record.last_outbound_sequence;
	request->envelope.policy_epoch =
		device->record.policy.envelope.policy_epoch;
	request->envelope.revocation_epoch =
		device->record.revocation_epoch;
	request->envelope.issued_at_ms = now_ms;
	request->envelope.expires_at_ms = expires_at_ms;
	memcpy(request->envelope.nonce, nonce,
	       sizeof(request->envelope.nonce));
	ret = pqcp_runtime_internal_copy_text(
		request->envelope.device_id,
		sizeof(request->envelope.device_id),
		device->device_id);
	if (ret == 0) ret = pqcp_runtime_internal_copy_text(
		request->envelope.domain_id,
		sizeof(request->envelope.domain_id),
		target_domain_id);
	if (ret == 0) ret = pqcp_runtime_internal_copy_text(
		request->firmware_version,
		sizeof(request->firmware_version),
		device->firmware_version);
	if (ret == 0) ret = pqcp_runtime_internal_copy_text(
		request->product_class,
		sizeof(request->product_class),
		device->product_class);
	if (ret != 0) return ret;
	request->stage =
		device->record.operational_key_valid ?
			PQCP_FLEET_ENROLLMENT_OPERATIONAL_KEY :
			PQCP_FLEET_ENROLLMENT_FACTORY;
	request->boot_counter = device->record.boot_counter;
	request->enrollment_counter =
		++device->record.enrollment_counter;
	request->supported_mlkem_mask = supported_mlkem_mask;
	request->supported_mldsa_mask = supported_mldsa_mask;
	request->requested_capabilities = requested_capabilities;
	memcpy(request->hardware_id_digest,
	       device->hardware_id_digest,
	       sizeof(request->hardware_id_digest));
	ret = export_key(device, &device->record.factory_key,
			 factory_public);
	if (ret == 0) {
		memcpy(request->factory_public_key, factory_public,
		       sizeof(request->factory_public_key));
		ret = pqcp_fleet_public_key_fingerprint(
			factory_public, request->factory_fingerprint);
	}
	if (ret == 0) {
		ret = export_key(
			device,
			device->record.pending_operational_key_valid ?
				&device->record.pending_operational_key :
				&device->record.operational_key,
			request->operational_public_key);
	}
	request->operational_key_present = ret == 0;
	if (ret == 0) ret = pqcp_fleet_runtime_signer_init(
		&signer, &signer_context,
		&device->runtime->key_store,
		&device->record.factory_key);
	if (ret == 0) ret = pqcp_fleet_enrollment_request_sign(
		request, &signer, now_ms);
	if (ret == 0) {
		device->record.pending_enrollment_message_id =
			message_id;
		memcpy(device->record.pending_enrollment_nonce, nonce,
		       sizeof(device->record.pending_enrollment_nonce));
		device->record.state = PQCP_FLEET_DEVICE_ENROLLING;
		ret = pqcp_fleet_store_commit(
			device->store, &device->record);
	}
	pqcp_runtime_secure_zero(factory_public,
				 sizeof(factory_public));
	return ret;
}

int pqcp_fleet_device_install_ownership(
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_ownership_voucher *voucher,
	const struct pqcp_fleet_credential *credential,
	uint64_t now_ms)
{
	uint8_t pending_public[PQCP_FLEET_PUBLIC_KEY_BYTES];
	uint8_t fingerprint[PQCP_FLEET_DIGEST_BYTES];
	int ret;

	if (device == NULL || !device->initialized ||
	    voucher == NULL || credential == NULL ||
	    !device->record.pending_operational_key_valid ||
	    device->record.pending_enrollment_message_id == 0U ||
	    strcmp(voucher->envelope.device_id,
		   device->device_id) != 0 ||
	    strcmp(credential->envelope.device_id,
		   device->device_id) != 0 ||
	    strcmp(voucher->envelope.domain_id,
		   credential->envelope.domain_id) != 0 ||
	    strcmp(voucher->product_class,
		   device->product_class) != 0 ||
	    strcmp(credential->product_class,
		   device->product_class) != 0 ||
	    memcmp(voucher->envelope.nonce,
		   device->record.pending_enrollment_nonce,
		   PQCP_FLEET_NONCE_BYTES) != 0 ||
	    memcmp(credential->envelope.nonce,
		   device->record.pending_enrollment_nonce,
		   PQCP_FLEET_NONCE_BYTES) != 0 ||
	    memcmp(voucher->factory_fingerprint,
		   device->record.factory_fingerprint,
		   PQCP_FLEET_DIGEST_BYTES) != 0 ||
	    voucher->envelope.sequence <=
		    device->record.last_inbound_sequence ||
	    credential->envelope.sequence <=
		    device->record.last_inbound_sequence ||
	    voucher->envelope.revocation_epoch <
		    device->record.revocation_epoch ||
	    credential->envelope.revocation_epoch <
		    device->record.revocation_epoch) {
		return -EINVAL;
	}
	if (memcmp(voucher->registrar_public_key,
		   device->record.registrar_public_key,
		   sizeof(device->record.registrar_public_key)) != 0) {
		return -EKEYREJECTED;
	}
	ret = pqcp_fleet_voucher_verify(
		voucher, device->record.registrar_public_key, now_ms);
	if (ret == 0) ret = pqcp_fleet_credential_verify(
		credential, device->record.registrar_public_key, now_ms);
	if (ret == 0) ret = export_key(
		device, &device->record.pending_operational_key,
		pending_public);
	if (ret == 0) ret = pqcp_fleet_public_key_fingerprint(
		pending_public, fingerprint);
	if (ret == 0 &&
	    (memcmp(fingerprint,
		    voucher->operational_key_fingerprint,
		    sizeof(fingerprint)) != 0 ||
	     memcmp(pending_public,
		    credential->subject_public_key,
		    sizeof(pending_public)) != 0 ||
	     (credential->capabilities &
	      ~voucher->granted_capabilities) != 0U)) {
		ret = -EKEYREJECTED;
	}
	if (ret != 0) return ret;
	device->record.credential = *credential;
	device->record.granted_capabilities =
		voucher->granted_capabilities;
	device->record.revocation_epoch =
		credential->envelope.revocation_epoch;
	device->record.last_inbound_sequence =
		voucher->envelope.sequence >
			credential->envelope.sequence ?
			voucher->envelope.sequence :
			credential->envelope.sequence;
	device->record.pending_enrollment_message_id = 0U;
	memset(device->record.pending_enrollment_nonce, 0,
	       sizeof(device->record.pending_enrollment_nonce));
	(void)pqcp_runtime_internal_copy_text(
		device->record.product_class,
		sizeof(device->record.product_class),
		voucher->product_class);
	if (device->record.operational_key_valid) {
		const struct pqcp_runtime_key_handle old =
			device->record.operational_key;
		device->record.operational_key =
			device->record.pending_operational_key;
		device->record.pending_operational_key = old;
		device->record.rotation_overlap_until_ms =
			now_ms + UINT64_C(86400000);
		device->record.state = PQCP_FLEET_DEVICE_ROTATING;
	} else {
		device->record.operational_key =
			device->record.pending_operational_key;
		memset(&device->record.pending_operational_key, 0,
		       sizeof(device->record.pending_operational_key));
		device->record.pending_operational_key_valid = false;
		device->record.operational_key_valid = true;
		device->record.state = PQCP_FLEET_DEVICE_OWNED;
	}
	return pqcp_fleet_store_commit(
		device->store, &device->record);
}

int pqcp_fleet_device_apply_policy(
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_policy_bundle *policy,
	uint64_t now_ms)
{
	int ret;

	if (device == NULL || !device->initialized ||
	    policy == NULL || !device->record.operational_key_valid) {
		return -EINVAL;
	}
	ret = pqcp_fleet_policy_verify(
		policy, device->record.registrar_public_key, now_ms);
	if (ret != 0) return ret;
	if ((strcmp(policy->envelope.device_id, "*") != 0 &&
	     strcmp(policy->envelope.device_id,
		    device->device_id) != 0) ||
	    strcmp(policy->envelope.domain_id,
		   device->record.credential.envelope.domain_id) != 0 ||
	    policy->envelope.revocation_epoch <
		    device->record.revocation_epoch ||
	    policy->envelope.policy_epoch <=
		    device->record.policy.envelope.policy_epoch ||
	    policy->envelope.sequence <=
		    device->record.last_inbound_sequence ||
	    (policy->required_capabilities &
	     ~device->record.granted_capabilities) != 0U ||
	    policy->maximum_sessions == 0U ||
	    policy->maximum_jobs == 0U) {
		return -ESTALE;
	}
	device->record.policy = *policy;
	device->record.last_inbound_sequence =
		policy->envelope.sequence;
	device->record.state =
		(policy->flags & PQCP_FLEET_POLICY_LOCKDOWN) != 0U ?
			PQCP_FLEET_DEVICE_RECOVERY :
			PQCP_FLEET_DEVICE_OPERATIONAL;
	device->runtime->controller.accepting_sessions =
		device->record.state ==
			PQCP_FLEET_DEVICE_OPERATIONAL;
	return pqcp_fleet_store_commit(
		device->store, &device->record);
}

static bool revocation_matches(
	const struct pqcp_fleet_store_record *record,
	const char *device_id,
	const struct pqcp_fleet_revocation_entry *entry)
{
	if (entry->kind == PQCP_FLEET_REVOKE_DEVICE) {
		return strcmp(entry->subject_id, device_id) == 0;
	}
	if (entry->kind == PQCP_FLEET_REVOKE_DOMAIN) {
		return strcmp(
			entry->subject_id,
			record->credential.envelope.domain_id) == 0;
	}
	return entry->kind == PQCP_FLEET_REVOKE_CREDENTIAL &&
	       strcmp(entry->subject_id,
		      record->credential.credential_id) == 0;
}

static void apply_due_revocations(
	struct pqcp_fleet_store_record *record,
	const char *device_id,
	uint64_t now_ms,
	bool *revoked,
	bool *changed)
{
	uint32_t retained = 0U;

	for (uint32_t index = 0U;
	     index < record->pending_revocation_count; ++index) {
		const struct pqcp_fleet_revocation_entry *entry =
			&record->pending_revocations[index];

		if (entry->effective_at_ms <= now_ms) {
			if (revocation_matches(record, device_id, entry)) {
				record->state = PQCP_FLEET_DEVICE_REVOKED;
				*revoked = true;
			}
			*changed = true;
			continue;
		}
		if (retained != index) {
			record->pending_revocations[retained] = *entry;
		}
		retained++;
	}
	if (retained != record->pending_revocation_count) {
		memset(
			&record->pending_revocations[retained], 0,
			sizeof(record->pending_revocations[0]) *
				(PQCP_FLEET_MAX_REVOCATIONS - retained));
		record->pending_revocation_count = retained;
	}
}

int pqcp_fleet_device_apply_revocation(
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_revocation_update *update,
	uint64_t now_ms)
{
	struct pqcp_fleet_store_record next;
	uint32_t future_count = 0U;
	bool revoked = false;
	bool changed = false;
	int ret;

	if (device == NULL || !device->initialized || update == NULL) {
		return -EINVAL;
	}
	ret = pqcp_fleet_revocation_verify(
		update, device->record.registrar_public_key, now_ms);
	if (ret != 0) return ret;
	if (strcmp(update->envelope.device_id,
		   device->device_id) != 0 ||
	    strcmp(update->envelope.domain_id,
		   device->record.credential.envelope.domain_id) != 0 ||
	    update->previous_epoch != device->record.revocation_epoch ||
	    update->envelope.revocation_epoch <=
		    device->record.revocation_epoch ||
	    update->envelope.sequence <=
		    device->record.last_inbound_sequence) {
		return -ESTALE;
	}
	next = device->record;
	apply_due_revocations(
		&next, device->device_id, now_ms,
		&revoked, &changed);
	for (size_t index = 0U; index < update->entry_count; ++index) {
		if (update->entries[index].effective_at_ms > now_ms) {
			future_count++;
		}
	}
	if (future_count >
	    PQCP_FLEET_MAX_REVOCATIONS -
		    next.pending_revocation_count) {
		return -ENOSPC;
	}
	next.revocation_epoch =
		update->envelope.revocation_epoch;
	next.revocation_refresh_due_ms =
		update->next_refresh_ms;
	next.offline_grace_ms = update->offline_grace_ms;
	next.last_inbound_sequence =
		update->envelope.sequence;
	for (size_t index = 0U; index < update->entry_count; ++index) {
		const struct pqcp_fleet_revocation_entry *entry =
			&update->entries[index];

		if (entry->effective_at_ms > now_ms) {
			next.pending_revocations[
				next.pending_revocation_count++] = *entry;
		} else if (revocation_matches(
				   &next, device->device_id, entry)) {
			next.state = PQCP_FLEET_DEVICE_REVOKED;
			revoked = true;
		}
	}
	ret = pqcp_fleet_store_commit(device->store, &next);
	if (ret != 0) {
		return ret;
	}
	device->record = next;
	if (revoked) {
		device->runtime->controller.accepting_sessions = false;
		(void)pqcp_runtime_session_mark_draining(
			&device->runtime->sessions,
			device->record.policy.preferred_profile);
	}
	return 0;
}

int pqcp_fleet_device_authorize_update(
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_update_manifest *manifest,
	uint64_t now_ms,
	struct pqcp_fleet_update_decision *decision)
{
	int ret;

	if (device == NULL || !device->initialized ||
	    manifest == NULL || decision == NULL) return -EINVAL;
	memset(decision, 0, sizeof(*decision));
	ret = pqcp_fleet_update_manifest_verify(
		manifest, device->record.registrar_public_key, now_ms);
	if (ret != 0) return ret;
	if (device->record.state != PQCP_FLEET_DEVICE_OPERATIONAL ||
	    strcmp(manifest->envelope.device_id,
		   device->device_id) != 0 ||
	    strcmp(manifest->envelope.domain_id,
		   device->record.credential.envelope.domain_id) != 0 ||
	    manifest->version <= device->record.current_firmware_version ||
	    manifest->version <= device->record.pending_update_version ||
	    device->record.current_firmware_version <
		    manifest->minimum_current_version ||
	    strcmp(manifest->product_class,
		   device->record.product_class) != 0 ||
	    (manifest->required_capabilities &
	     ~device->record.granted_capabilities) != 0U ||
	    manifest->envelope.sequence <=
		    device->record.last_inbound_sequence ||
	    manifest->envelope.policy_epoch !=
		    device->record.policy.envelope.policy_epoch ||
	    manifest->envelope.revocation_epoch <
		    device->record.revocation_epoch) {
		return -EACCES;
	}
	decision->version = manifest->version;
	decision->image_size = manifest->image_size;
	decision->flags = manifest->flags;
	memcpy(decision->image_digest, manifest->image_digest,
	       sizeof(decision->image_digest));
	decision->authorized = true;
	device->record.pending_update_version = manifest->version;
	device->record.pending_update_image_size = manifest->image_size;
	device->record.pending_update_flags = manifest->flags;
	memcpy(device->record.pending_update_digest,
	       manifest->image_digest,
	       sizeof(device->record.pending_update_digest));
	device->record.pending_update_valid = true;
	device->record.last_inbound_sequence =
		manifest->envelope.sequence;
	return pqcp_fleet_store_commit(
		device->store, &device->record);
}

int pqcp_fleet_device_complete_update(
	struct pqcp_fleet_device *device,
	bool installed,
	uint64_t now_ms)
{
	ARG_UNUSED(now_ms);

	if (device == NULL || !device->initialized ||
	    !device->record.pending_update_valid) {
		return -EINVAL;
	}
	if (installed) {
		device->record.current_firmware_version =
			device->record.pending_update_version;
	}
	device->record.pending_update_version = 0U;
	device->record.pending_update_image_size = 0U;
	device->record.pending_update_flags = 0U;
	memset(device->record.pending_update_digest, 0,
	       sizeof(device->record.pending_update_digest));
	device->record.pending_update_valid = false;
	return pqcp_fleet_store_commit(
		device->store, &device->record);
}

int pqcp_fleet_device_begin_rotation(
	struct pqcp_fleet_device *device,
	const uint8_t nonce[PQCP_FLEET_NONCE_BYTES],
	uint64_t message_id, uint64_t now_ms,
	uint64_t expires_at_ms, uint64_t requested_overlap_ms,
	struct pqcp_fleet_rotation_request *request)
{
	struct pqcp_fleet_signer signer;
	struct pqcp_fleet_runtime_signer_context signer_context;
	uint8_t current_public[PQCP_FLEET_PUBLIC_KEY_BYTES];
	int ret;

	if (device == NULL || !device->initialized ||
	    nonce == NULL || request == NULL ||
	    device->record.state != PQCP_FLEET_DEVICE_OPERATIONAL ||
	    expires_at_ms <= now_ms || requested_overlap_ms == 0U) {
		return -EINVAL;
	}
	ret = generate_operational_key(
		device, now_ms,
		&device->record.pending_operational_key);
	if (ret != 0) return ret;
	device->record.pending_operational_key_valid = true;
	memset(request, 0, sizeof(*request));
	request->envelope.schema_version = PQCP_FLEET_SCHEMA_VERSION;
	request->envelope.protocol_version = PQCP_FLEET_PROTOCOL_VERSION;
	request->envelope.type = PQCP_FLEET_MESSAGE_ROTATION_REQUEST;
	request->envelope.message_id = message_id;
	request->envelope.sequence =
		++device->record.last_outbound_sequence;
	request->envelope.policy_epoch =
		device->record.policy.envelope.policy_epoch;
	request->envelope.revocation_epoch =
		device->record.revocation_epoch;
	request->envelope.issued_at_ms = now_ms;
	request->envelope.expires_at_ms = expires_at_ms;
	memcpy(request->envelope.nonce, nonce,
	       sizeof(request->envelope.nonce));
	(void)pqcp_runtime_internal_copy_text(
		request->envelope.device_id,
		sizeof(request->envelope.device_id), device->device_id);
	(void)pqcp_runtime_internal_copy_text(
		request->envelope.domain_id,
		sizeof(request->envelope.domain_id),
		device->record.credential.envelope.domain_id);
	(void)pqcp_runtime_internal_copy_text(
		request->current_credential_id,
		sizeof(request->current_credential_id),
		device->record.credential.credential_id);
	ret = export_key(
		device, &device->record.operational_key, current_public);
	if (ret == 0) ret = pqcp_fleet_public_key_fingerprint(
		current_public, request->current_key_fingerprint);
	if (ret == 0) ret = export_key(
		device, &device->record.pending_operational_key,
		request->new_operational_public_key);
	request->requested_overlap_ms = requested_overlap_ms;
	if (ret == 0) ret = pqcp_fleet_runtime_signer_init(
		&signer, &signer_context,
		&device->runtime->key_store,
		&device->record.operational_key);
	if (ret == 0) ret = pqcp_fleet_rotation_request_sign(
		request, &signer, now_ms);
	if (ret == 0) {
		device->record.pending_rotation_message_id =
			message_id;
		memcpy(device->record.pending_rotation_nonce, nonce,
		       sizeof(device->record.pending_rotation_nonce));
		device->record.state = PQCP_FLEET_DEVICE_ROTATING;
		ret = pqcp_fleet_store_commit(
			device->store, &device->record);
	}
	return ret;
}

int pqcp_fleet_device_complete_rotation(
	struct pqcp_fleet_device *device,
	const struct pqcp_fleet_rotation_authorization *authorization,
	const struct pqcp_fleet_credential *replacement_credential,
	uint64_t now_ms)
{
	uint8_t old_public[PQCP_FLEET_PUBLIC_KEY_BYTES];
	uint8_t new_public[PQCP_FLEET_PUBLIC_KEY_BYTES] = { 0 };
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	struct pqcp_runtime_key_handle old;
	int ret;

	if (device == NULL || authorization == NULL ||
	    replacement_credential == NULL ||
	    !device->record.pending_operational_key_valid ||
	    device->record.state != PQCP_FLEET_DEVICE_ROTATING) {
		return -EINVAL;
	}
	if (strcmp(authorization->envelope.device_id,
		   device->device_id) != 0 ||
	    strcmp(replacement_credential->envelope.device_id,
		   device->device_id) != 0 ||
	    strcmp(authorization->replacement_credential_id,
		   replacement_credential->credential_id) != 0 ||
	    strcmp(authorization->envelope.domain_id,
		   device->record.credential.envelope.domain_id) != 0 ||
	    strcmp(replacement_credential->envelope.domain_id,
		   device->record.credential.envelope.domain_id) != 0 ||
	    strcmp(replacement_credential->product_class,
		   device->record.product_class) != 0 ||
	    memcmp(authorization->envelope.nonce,
		   device->record.pending_rotation_nonce,
		   PQCP_FLEET_NONCE_BYTES) != 0 ||
	    memcmp(replacement_credential->envelope.nonce,
		   device->record.pending_rotation_nonce,
		   PQCP_FLEET_NONCE_BYTES) != 0 ||
	    authorization->envelope.sequence <=
		    device->record.last_inbound_sequence ||
	    replacement_credential->envelope.sequence <=
		    device->record.last_inbound_sequence ||
	    authorization->envelope.policy_epoch !=
		    device->record.policy.envelope.policy_epoch ||
	    replacement_credential->envelope.policy_epoch !=
		    device->record.policy.envelope.policy_epoch ||
	    authorization->envelope.revocation_epoch <
		    device->record.revocation_epoch ||
	    replacement_credential->envelope.revocation_epoch <
		    device->record.revocation_epoch ||
	    replacement_credential->issuance_epoch <=
		    device->record.credential.issuance_epoch ||
	    (replacement_credential->capabilities &
	     ~device->record.granted_capabilities) != 0U) {
		return -EKEYREJECTED;
	}
	ret = pqcp_fleet_rotation_authorization_verify(
		authorization, device->record.registrar_public_key, now_ms);
	if (ret == 0) ret = pqcp_fleet_credential_verify(
		replacement_credential,
		device->record.registrar_public_key, now_ms);
	if (ret == 0) ret = export_key(
		device, &device->record.operational_key, old_public);
	if (ret == 0) ret = pqcp_fleet_public_key_fingerprint(
		old_public, digest);
	if (ret == 0 &&
	    memcmp(digest, authorization->old_key_fingerprint,
		   sizeof(digest)) != 0) ret = -EKEYREJECTED;
	if (ret == 0) ret = export_key(
		device, &device->record.pending_operational_key,
		new_public);
	if (ret == 0) ret = pqcp_fleet_public_key_fingerprint(
		new_public, digest);
	if (ret == 0 &&
	    (memcmp(digest, authorization->new_key_fingerprint,
		    sizeof(digest)) != 0 ||
	     memcmp(new_public,
		    replacement_credential->subject_public_key,
		    sizeof(new_public)) != 0)) ret = -EKEYREJECTED;
	if (ret != 0) return ret;
	old = device->record.operational_key;
	device->record.operational_key =
		device->record.pending_operational_key;
	device->record.pending_operational_key = old;
	device->record.credential = *replacement_credential;
	device->record.rotation_overlap_until_ms =
		authorization->overlap_until_ms;
	device->record.last_inbound_sequence =
		authorization->envelope.sequence >
			replacement_credential->envelope.sequence ?
			authorization->envelope.sequence :
			replacement_credential->envelope.sequence;
	device->record.pending_rotation_message_id = 0U;
	memset(device->record.pending_rotation_nonce, 0,
	       sizeof(device->record.pending_rotation_nonce));
	device->record.operational_key_valid = true;
	device->record.pending_operational_key_valid = true;
	return pqcp_fleet_store_commit(
		device->store, &device->record);
}

int pqcp_fleet_device_configure_channel(
	struct pqcp_fleet_device *device,
	struct pqcp_channel_config *config)
{
	if (device == NULL || !device->initialized || config == NULL ||
	    device->record.state != PQCP_FLEET_DEVICE_OPERATIONAL ||
	    !device->record.operational_key_valid) {
		return -EACCES;
	}
	config->local_identity = device->record.operational_key;
	config->mldsa_level = PQCP_FLEET_MLDSA_LEVEL;
	memcpy(config->peer_identity_public,
	       device->record.registrar_public_key,
	       PQCP_FLEET_PUBLIC_KEY_BYTES);
	config->peer_identity_public_length =
		PQCP_FLEET_PUBLIC_KEY_BYTES;
	return pqcp_runtime_internal_copy_text(
		config->profile_id, sizeof(config->profile_id),
		device->record.policy.preferred_profile);
}

int pqcp_fleet_device_tick(
	struct pqcp_fleet_device *device, uint64_t now_ms)
{
	struct pqcp_fleet_store_record next;
	bool changed = false;
	bool revoked = false;
	bool recovery = false;
	int ret = 0;

	if (device == NULL || !device->initialized) return -EINVAL;
	next = device->record;
	apply_due_revocations(
		&next, device->device_id, now_ms,
		&revoked, &changed);
	if (next.state == PQCP_FLEET_DEVICE_ROTATING &&
	    next.pending_operational_key_valid &&
	    next.rotation_overlap_until_ms != 0U &&
	    now_ms >= next.rotation_overlap_until_ms) {
		ret = pqcp_runtime_key_store_destroy(
			&device->runtime->key_store,
			&next.pending_operational_key);
		if (ret == 0) {
			memset(&next.pending_operational_key, 0,
			       sizeof(next.pending_operational_key));
			next.pending_operational_key_valid = false;
			next.rotation_overlap_until_ms = 0U;
			next.state =
				PQCP_FLEET_DEVICE_OPERATIONAL;
			changed = true;
		}
	}
	if (ret == 0 &&
	    next.revocation_refresh_due_ms != 0U &&
	    now_ms > next.revocation_refresh_due_ms &&
	    now_ms - next.revocation_refresh_due_ms >
		    next.offline_grace_ms &&
	    next.state != PQCP_FLEET_DEVICE_RECOVERY &&
	    next.state != PQCP_FLEET_DEVICE_REVOKED &&
	    next.state != PQCP_FLEET_DEVICE_DECOMMISSIONED) {
		next.state = PQCP_FLEET_DEVICE_RECOVERY;
		recovery = true;
		changed = true;
	}
	if (ret != 0 || !changed) {
		return ret;
	}
	ret = pqcp_fleet_store_commit(device->store, &next);
	if (ret != 0) {
		return ret;
	}
	device->record = next;
	if (revoked || recovery) {
		device->runtime->controller.accepting_sessions = false;
	}
	if (revoked) {
		(void)pqcp_runtime_session_mark_draining(
			&device->runtime->sessions,
			device->record.policy.preferred_profile);
	}
	return 0;
}

int pqcp_fleet_device_decommission(
	struct pqcp_fleet_device *device, uint64_t now_ms)
{
	ARG_UNUSED(now_ms);
	if (device == NULL || !device->initialized) return -EINVAL;
	device->runtime->controller.accepting_sessions = false;
	for (size_t index = 0U;
	     index < device->runtime->sessions.capacity; ++index) {
		if (device->runtime->sessions.sessions[index].active) {
			(void)pqcp_runtime_session_close(
				&device->runtime->sessions,
				device->runtime->sessions.sessions[index].session_id);
		}
	}
	if (device->record.pending_operational_key_valid) {
		(void)pqcp_runtime_key_store_destroy(
			&device->runtime->key_store,
			&device->record.pending_operational_key);
	}
	if (device->record.operational_key_valid) {
		(void)pqcp_runtime_key_store_destroy(
			&device->runtime->key_store,
			&device->record.operational_key);
	}
	device->record.state = PQCP_FLEET_DEVICE_DECOMMISSIONED;
	device->record.operational_key_valid = false;
	device->record.pending_operational_key_valid = false;
	device->record.pending_update_valid = false;
	pqcp_runtime_secure_zero(
		&device->record.credential,
		sizeof(device->record.credential));
	pqcp_runtime_secure_zero(
		&device->record.policy,
		sizeof(device->record.policy));
	return pqcp_fleet_store_commit(
		device->store, &device->record);
}

int pqcp_fleet_device_audit(
	const struct pqcp_fleet_device *device, uint64_t now_ms)
{
	if (device == NULL || !device->initialized ||
	    !pqcp_runtime_internal_text_valid(
		    device->device_id, sizeof(device->device_id)) ||
	    device->record.state > PQCP_FLEET_DEVICE_DECOMMISSIONED ||
	    (device->record.state == PQCP_FLEET_DEVICE_OPERATIONAL &&
	     (!device->record.operational_key_valid ||
	      device->record.credential.valid_until_ms <= now_ms ||
	      device->record.policy.envelope.policy_epoch == 0U))) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_fleet_channel_send(
	struct pqcp_channel *channel,
	const uint8_t *message, size_t message_length,
	uint32_t message_id)
{
	return message_length <= PQCP_FLEET_MESSAGE_MAX_BYTES ?
		pqcp_channel_send_message(
			channel, message, message_length, message_id) :
		-EMSGSIZE;
}

int pqcp_fleet_channel_receive(
	struct pqcp_channel *channel,
	uint8_t *message, size_t message_capacity,
	size_t *message_length, uint32_t *message_id)
{
	return message_capacity >= PQCP_FLEET_MESSAGE_MAX_BYTES ?
		pqcp_channel_receive_message(
			channel, message, message_capacity,
			message_length, message_id) :
		-EMSGSIZE;
}
