/*
 * SPDX-License-Identifier: MIT
 *
 * Gateway-side fleet registrar.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <pqcp_zephyr/fleet_enrollment.h>
#include <pqcp_zephyr/fleet_registrar.h>
#include <pqcp_zephyr/rng.h>

#include "runtime_internal.h"

static int signer_for(
	struct pqcp_fleet_registrar *registrar,
	struct pqcp_fleet_signer *signer,
	struct pqcp_fleet_runtime_signer_context *context)
{
	return pqcp_fleet_runtime_signer_init(
		signer, context, &registrar->runtime->key_store,
		&registrar->signer->local_key);
}

static int copy_text(char *output, size_t capacity, const char *input)
{
	return pqcp_runtime_internal_copy_text(output, capacity, input);
}

static int fill_envelope(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id,
	enum pqcp_fleet_message_type type,
	uint64_t now_ms, uint64_t lifetime_ms,
	struct pqcp_fleet_envelope *envelope)
{
	if (lifetime_ms == 0U || UINT64_MAX - now_ms < lifetime_ms) {
		return -EINVAL;
	}
	memset(envelope, 0, sizeof(*envelope));
	envelope->schema_version = PQCP_FLEET_SCHEMA_VERSION;
	envelope->protocol_version = PQCP_FLEET_PROTOCOL_VERSION;
	envelope->type = type;
	envelope->message_id = registrar->next_message_id++;
	envelope->sequence = envelope->message_id;
	envelope->policy_epoch = registrar->policy_epoch;
	envelope->revocation_epoch = registrar->revocation_epoch;
	envelope->issued_at_ms = now_ms;
	envelope->expires_at_ms = now_ms + lifetime_ms;
	if (pqcp_rng_get_bytes(
		    envelope->nonce, sizeof(envelope->nonce)) != 0 ||
	    copy_text(envelope->device_id,
		      sizeof(envelope->device_id), device_id) != 0 ||
	    copy_text(envelope->domain_id,
		      sizeof(envelope->domain_id),
		      registrar->config.domain_id) != 0) {
		return -EIO;
	}
	return 0;
}

struct pqcp_fleet_device_record *pqcp_fleet_registrar_find(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id)
{
	if (registrar == NULL || device_id == NULL) {
		return NULL;
	}
	for (size_t index = 0U; index < registrar->capacity; ++index) {
		if (registrar->records[index].occupied &&
		    strcmp(registrar->records[index].device_id,
			   device_id) == 0) {
			return &registrar->records[index];
		}
	}
	return NULL;
}

int pqcp_fleet_registrar_init(
	struct pqcp_fleet_registrar *registrar,
	const struct pqcp_fleet_registrar_config *config,
	struct pqcp_runtime_service *runtime,
	struct pqcp_fleet_device_record *records,
	size_t capacity)
{
	struct pqcp_runtime_identity *signer;

	if (registrar == NULL || config == NULL ||
	    runtime == NULL || !runtime->initialized ||
	    records == NULL || capacity == 0U ||
	    !pqcp_runtime_internal_text_valid(
		    config->domain_id, sizeof(config->domain_id)) ||
	    config->voucher_lifetime_ms == 0U ||
	    config->credential_lifetime_ms == 0U ||
	    config->default_capabilities == 0U ||
	    config->allowed_mlkem_mask == 0U ||
	    config->allowed_mldsa_mask == 0U) {
		return -EINVAL;
	}
	signer = pqcp_runtime_identity_find(
		&runtime->identities, config->signing_identity_id);
	if (signer == NULL || !signer->active || !signer->local ||
	    signer->mldsa_level != PQCP_FLEET_MLDSA_LEVEL) {
		return -ENOENT;
	}
	memset(registrar, 0, sizeof(*registrar));
	memset(records, 0, sizeof(*records) * capacity);
	registrar->schema_version = PQCP_FLEET_SCHEMA_VERSION;
	registrar->config = *config;
	registrar->runtime = runtime;
	registrar->signer = signer;
	registrar->records = records;
	registrar->capacity = capacity;
	registrar->next_message_id = 1U;
	registrar->policy_epoch = 1U;
	registrar->revocation_epoch = 1U;
	k_mutex_init(&registrar->lock);
	registrar->initialized = true;
	return 0;
}

int pqcp_fleet_registrar_public_key(
	const struct pqcp_fleet_registrar *registrar,
	uint8_t public_key[PQCP_FLEET_PUBLIC_KEY_BYTES])
{
	if (registrar == NULL || !registrar->initialized ||
	    public_key == NULL ||
	    registrar->signer->peer_public_key_length !=
		    PQCP_FLEET_PUBLIC_KEY_BYTES) {
		return -EINVAL;
	}
	memcpy(public_key, registrar->signer->peer_public_key,
	       PQCP_FLEET_PUBLIC_KEY_BYTES);
	return 0;
}

int pqcp_fleet_registrar_admit_factory(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id, const char *product_class,
	const uint8_t factory_public_key[PQCP_FLEET_PUBLIC_KEY_BYTES],
	const uint8_t hardware_id_digest[PQCP_FLEET_DIGEST_BYTES],
	uint32_t capabilities)
{
	struct pqcp_fleet_device_record *record = NULL;

	if (registrar == NULL || !registrar->initialized ||
	    device_id == NULL || product_class == NULL ||
	    factory_public_key == NULL || hardware_id_digest == NULL ||
	    capabilities == 0U ||
	    pqcp_fleet_registrar_find(registrar, device_id) != NULL) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < registrar->capacity; ++index) {
		if (!registrar->records[index].occupied) {
			record = &registrar->records[index];
			break;
		}
	}
	if (record == NULL) {
		return -ENOSPC;
	}
	memset(record, 0, sizeof(*record));
	record->schema_version = PQCP_FLEET_SCHEMA_VERSION;
	record->state = PQCP_FLEET_REGISTRAR_DEVICE_ADMITTED;
	record->granted_capabilities =
		capabilities & registrar->config.default_capabilities;
	if (record->granted_capabilities == 0U ||
	    copy_text(record->device_id, sizeof(record->device_id),
		      device_id) != 0 ||
	    copy_text(record->product_class,
		      sizeof(record->product_class),
		      product_class) != 0) {
		return -EINVAL;
	}
	memcpy(record->factory_public_key, factory_public_key,
	       sizeof(record->factory_public_key));
	memcpy(record->hardware_id_digest, hardware_id_digest,
	       sizeof(record->hardware_id_digest));
	(void)pqcp_fleet_public_key_fingerprint(
		record->factory_public_key,
		record->factory_fingerprint);
	record->occupied = true;
	return 0;
}

static int verify_request(
	struct pqcp_fleet_registrar *registrar,
	const struct pqcp_fleet_enrollment_request *request,
	uint64_t now_ms,
	bool allow_vouchered_reuse,
	struct pqcp_fleet_device_record **record)
{
	uint8_t fingerprint[PQCP_FLEET_DIGEST_BYTES] = { 0 };
	int ret;

	*record = pqcp_fleet_registrar_find(
		registrar, request->envelope.device_id);
	if (*record == NULL ||
	    strcmp(request->envelope.domain_id,
		   registrar->config.domain_id) != 0 ||
	    strcmp(request->product_class,
		   (*record)->product_class) != 0 ||
	    request->envelope.sequence < (*record)->last_sequence ||
	    (request->envelope.sequence ==
		     (*record)->last_sequence &&
	     (!allow_vouchered_reuse ||
	      (*record)->state !=
		      PQCP_FLEET_REGISTRAR_DEVICE_VOUCHERED))) {
		return -EACCES;
	}
	ret = pqcp_fleet_enrollment_request_verify(
		request, (*record)->factory_public_key, now_ms);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_fleet_public_key_fingerprint(
		request->factory_public_key, fingerprint);
	if (ret != 0 ||
	    memcmp(fingerprint, (*record)->factory_fingerprint,
		   sizeof(fingerprint)) != 0 ||
	    memcmp(request->factory_fingerprint,
		   (*record)->factory_fingerprint,
		   sizeof(fingerprint)) != 0 ||
	    memcmp(request->hardware_id_digest,
		   (*record)->hardware_id_digest,
		   sizeof((*record)->hardware_id_digest)) != 0) {
		return -EKEYREJECTED;
	}
	return 0;
}

int pqcp_fleet_registrar_issue_voucher(
	struct pqcp_fleet_registrar *registrar,
	const struct pqcp_fleet_enrollment_request *request,
	uint64_t now_ms,
	struct pqcp_fleet_ownership_voucher *voucher)
{
	struct pqcp_fleet_device_record *record;
	struct pqcp_fleet_signer signer;
	struct pqcp_fleet_runtime_signer_context signer_context;
	int ret;

	if (registrar == NULL || request == NULL || voucher == NULL) {
		return -EINVAL;
	}
	ret = verify_request(
		registrar, request, now_ms, false, &record);
	if (ret != 0 || !request->operational_key_present) {
		return ret != 0 ? ret : -EINVAL;
	}
	memset(voucher, 0, sizeof(*voucher));
	ret = fill_envelope(
		registrar, record->device_id,
		PQCP_FLEET_MESSAGE_OWNERSHIP_VOUCHER,
		now_ms, registrar->config.voucher_lifetime_ms,
		&voucher->envelope);
	if (ret != 0) return ret;
	memcpy(voucher->envelope.nonce,
	       request->envelope.nonce,
	       sizeof(voucher->envelope.nonce));
	memcpy(voucher->factory_fingerprint,
	       record->factory_fingerprint,
	       sizeof(voucher->factory_fingerprint));
	(void)pqcp_fleet_public_key_fingerprint(
		request->operational_public_key,
		voucher->operational_key_fingerprint);
	memcpy(voucher->registrar_public_key,
	       registrar->signer->peer_public_key,
	       sizeof(voucher->registrar_public_key));
	voucher->granted_capabilities =
		record->granted_capabilities &
		request->requested_capabilities;
	ret = copy_text(voucher->product_class,
			sizeof(voucher->product_class),
			record->product_class);
	if (ret == 0) ret = signer_for(
		registrar, &signer, &signer_context);
	if (ret == 0) ret = pqcp_fleet_voucher_sign(
		voucher, &signer, now_ms);
	if (ret == 0) {
		memcpy(record->operational_public_key,
		       request->operational_public_key,
		       sizeof(record->operational_public_key));
		record->operational_key_present = true;
		record->last_sequence =
			request->envelope.sequence;
		record->state = PQCP_FLEET_REGISTRAR_DEVICE_VOUCHERED;
	}
	return ret;
}

int pqcp_fleet_registrar_issue_credential(
	struct pqcp_fleet_registrar *registrar,
	const struct pqcp_fleet_enrollment_request *request,
	uint64_t now_ms, struct pqcp_fleet_credential *credential)
{
	struct pqcp_fleet_device_record *record;
	struct pqcp_fleet_signer signer;
	struct pqcp_fleet_runtime_signer_context signer_context;
	uint64_t next_credential_epoch;
	int ret = verify_request(
		registrar, request, now_ms, true, &record);

	if (ret != 0 || credential == NULL ||
	    !request->operational_key_present) {
		return ret != 0 ? ret : -EINVAL;
	}
	if (record->credential_epoch == UINT64_MAX) {
		return -EOVERFLOW;
	}
	next_credential_epoch = record->credential_epoch + 1U;
	memset(credential, 0, sizeof(*credential));
	ret = fill_envelope(
		registrar, record->device_id,
		PQCP_FLEET_MESSAGE_OPERATIONAL_CREDENTIAL,
		now_ms, registrar->config.credential_lifetime_ms,
		&credential->envelope);
	if (ret != 0) return ret;
	memcpy(credential->envelope.nonce,
	       request->envelope.nonce,
	       sizeof(credential->envelope.nonce));
	(void)snprintf(
		credential->credential_id,
		sizeof(credential->credential_id),
		"cred-%llu",
		(unsigned long long)credential->envelope.message_id);
	memcpy(credential->subject_public_key,
	       request->operational_public_key,
	       sizeof(credential->subject_public_key));
	credential->allowed_mlkem_mask =
		request->supported_mlkem_mask &
		registrar->config.allowed_mlkem_mask;
	credential->allowed_mldsa_mask =
		request->supported_mldsa_mask &
		registrar->config.allowed_mldsa_mask;
	credential->capabilities =
		request->requested_capabilities &
		record->granted_capabilities;
	credential->valid_from_ms = now_ms;
	credential->valid_until_ms =
		now_ms + registrar->config.credential_lifetime_ms;
	credential->issuance_epoch = next_credential_epoch;
	ret = copy_text(credential->product_class,
			sizeof(credential->product_class),
			record->product_class);
	if (ret == 0) ret = signer_for(
		registrar, &signer, &signer_context);
	if (ret == 0) ret = pqcp_fleet_credential_sign(
		credential, &signer, now_ms);
	if (ret == 0) {
		record->active_credential = *credential;
		record->credential_epoch = next_credential_epoch;
		record->revocation_epoch =
			credential->envelope.revocation_epoch;
		record->last_sequence =
			request->envelope.sequence;
		memcpy(record->operational_public_key,
		       request->operational_public_key,
		       sizeof(record->operational_public_key));
		record->operational_key_present = true;
		record->state = PQCP_FLEET_REGISTRAR_DEVICE_OPERATIONAL;
	}
	return ret;
}

int pqcp_fleet_registrar_issue_policy(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id,
	const struct pqcp_fleet_policy_bundle *template_policy,
	uint64_t now_ms, struct pqcp_fleet_policy_bundle *policy)
{
	struct pqcp_fleet_device_record *record =
		pqcp_fleet_registrar_find(registrar, device_id);
	struct pqcp_fleet_signer signer;
	struct pqcp_fleet_runtime_signer_context signer_context;
	uint64_t next_policy_epoch;
	int ret;

	if (record == NULL || template_policy == NULL || policy == NULL ||
	    record->state != PQCP_FLEET_REGISTRAR_DEVICE_OPERATIONAL) {
		return -EINVAL;
	}
	if (registrar->policy_epoch == UINT64_MAX) {
		return -EOVERFLOW;
	}
	next_policy_epoch = registrar->policy_epoch + 1U;
	*policy = *template_policy;
	ret = fill_envelope(
		registrar, device_id, PQCP_FLEET_MESSAGE_POLICY_BUNDLE,
		now_ms, registrar->config.credential_lifetime_ms,
		&policy->envelope);
	if (ret == 0) {
		policy->envelope.policy_epoch =
			next_policy_epoch;
		ret = signer_for(
			registrar, &signer, &signer_context);
	}
	if (ret == 0) ret = pqcp_fleet_policy_sign(
		policy, &signer, now_ms);
	if (ret == 0) {
		registrar->policy_epoch = next_policy_epoch;
		record->policy_epoch = next_policy_epoch;
	}
	return ret;
}

int pqcp_fleet_registrar_issue_revocation(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id,
	enum pqcp_fleet_revocation_kind kind,
	const char *subject_id, uint32_t reason,
	uint64_t now_ms,
	struct pqcp_fleet_revocation_update *update)
{
	struct pqcp_fleet_device_record *record =
		pqcp_fleet_registrar_find(registrar, device_id);
	struct pqcp_fleet_signer signer;
	struct pqcp_fleet_runtime_signer_context signer_context;
	uint64_t next_revocation_epoch;
	int ret;

	if (record == NULL || subject_id == NULL || update == NULL) {
		return -EINVAL;
	}
	if (record->revocation_epoch == UINT64_MAX ||
	    UINT64_MAX - now_ms < UINT64_C(172800000)) {
		return -EOVERFLOW;
	}
	next_revocation_epoch = record->revocation_epoch + 1U;
	memset(update, 0, sizeof(*update));
	update->previous_epoch = record->revocation_epoch;
	ret = fill_envelope(
		registrar, device_id,
		PQCP_FLEET_MESSAGE_REVOCATION_UPDATE,
		now_ms, registrar->config.credential_lifetime_ms,
		&update->envelope);
	if (ret != 0) return ret;
	update->envelope.revocation_epoch = next_revocation_epoch;
	update->next_refresh_ms = now_ms + UINT64_C(86400000);
	update->offline_grace_ms = UINT64_C(172800000);
	update->entry_count = 1U;
	update->entries[0].kind = kind;
	update->entries[0].effective_at_ms = now_ms;
	update->entries[0].reason = reason;
	ret = copy_text(update->entries[0].subject_id,
			sizeof(update->entries[0].subject_id), subject_id);
	if (ret == 0) ret = signer_for(
		registrar, &signer, &signer_context);
	if (ret == 0) ret = pqcp_fleet_revocation_sign(
		update, &signer, now_ms);
	if (ret == 0) {
		record->revocation_epoch = next_revocation_epoch;
		if (next_revocation_epoch >
		    registrar->revocation_epoch) {
			registrar->revocation_epoch =
				next_revocation_epoch;
		}
	}
	return ret;
}

int pqcp_fleet_registrar_issue_update(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id, const char *component_id,
	uint64_t version, uint64_t minimum_current_version,
	uint64_t image_size,
	const uint8_t image_digest[PQCP_FLEET_DIGEST_BYTES],
	uint32_t flags, uint64_t now_ms,
	struct pqcp_fleet_update_manifest *manifest)
{
	struct pqcp_fleet_device_record *record =
		pqcp_fleet_registrar_find(registrar, device_id);
	struct pqcp_fleet_signer signer;
	struct pqcp_fleet_runtime_signer_context signer_context;
	int ret;

	if (record == NULL || component_id == NULL ||
	    image_digest == NULL || manifest == NULL ||
	    version == 0U || image_size == 0U) {
		return -EINVAL;
	}
	memset(manifest, 0, sizeof(*manifest));
	ret = fill_envelope(
		registrar, device_id,
		PQCP_FLEET_MESSAGE_UPDATE_MANIFEST,
		now_ms, registrar->config.credential_lifetime_ms,
		&manifest->envelope);
	if (ret != 0) return ret;
	ret = copy_text(manifest->component_id,
			sizeof(manifest->component_id), component_id);
	if (ret == 0) ret = copy_text(
		manifest->product_class,
		sizeof(manifest->product_class),
		record->product_class);
	manifest->version = version;
	manifest->minimum_current_version = minimum_current_version;
	manifest->image_size = image_size;
	manifest->required_capabilities =
		PQCP_FLEET_CAP_FIRMWARE_UPDATE;
	manifest->flags = flags;
	memcpy(manifest->image_digest, image_digest,
	       sizeof(manifest->image_digest));
	if (ret == 0) ret = signer_for(
		registrar, &signer, &signer_context);
	if (ret == 0) ret = pqcp_fleet_update_manifest_sign(
		manifest, &signer, now_ms);
	return ret;
}

int pqcp_fleet_registrar_authorize_rotation(
	struct pqcp_fleet_registrar *registrar,
	const struct pqcp_fleet_rotation_request *request,
	uint64_t now_ms,
	struct pqcp_fleet_rotation_authorization *authorization,
	struct pqcp_fleet_credential *replacement_credential)
{
	struct pqcp_fleet_device_record *record;
	struct pqcp_fleet_signer signer;
	struct pqcp_fleet_runtime_signer_context signer_context;
	uint8_t fingerprint[PQCP_FLEET_DIGEST_BYTES] = { 0 };
	uint64_t overlap_ms;
	int ret;

	if (registrar == NULL || !registrar->initialized ||
	    request == NULL || authorization == NULL ||
	    replacement_credential == NULL) {
		return -EINVAL;
	}
	record = pqcp_fleet_registrar_find(
		registrar, request->envelope.device_id);
	if (record == NULL ||
	    record->state !=
		    PQCP_FLEET_REGISTRAR_DEVICE_OPERATIONAL ||
	    strcmp(request->envelope.domain_id,
		   registrar->config.domain_id) != 0 ||
	    strcmp(request->current_credential_id,
		   record->active_credential.credential_id) != 0 ||
	    request->envelope.sequence <= record->last_sequence ||
	    request->envelope.policy_epoch != record->policy_epoch ||
	    request->envelope.revocation_epoch <
		    record->revocation_epoch) {
		return -EACCES;
	}
	ret = pqcp_fleet_rotation_request_verify(
		request, record->operational_public_key, now_ms);
	if (ret == 0) {
		ret = pqcp_fleet_public_key_fingerprint(
			record->operational_public_key, fingerprint);
	}
	if (ret == 0 &&
	    memcmp(fingerprint, request->current_key_fingerprint,
		   sizeof(fingerprint)) != 0) {
		ret = -EKEYREJECTED;
	}
	if (ret != 0) {
		return ret;
	}
	overlap_ms = request->requested_overlap_ms <
			registrar->config.credential_lifetime_ms ?
			request->requested_overlap_ms :
			registrar->config.credential_lifetime_ms;

	memset(replacement_credential, 0,
	       sizeof(*replacement_credential));
	ret = fill_envelope(
		registrar, record->device_id,
		PQCP_FLEET_MESSAGE_OPERATIONAL_CREDENTIAL,
		now_ms, registrar->config.credential_lifetime_ms,
		&replacement_credential->envelope);
	if (ret == 0) {
		memcpy(replacement_credential->envelope.nonce,
		       request->envelope.nonce,
		       sizeof(replacement_credential->envelope.nonce));
		(void)snprintf(
			replacement_credential->credential_id,
			sizeof(replacement_credential->credential_id),
			"cred-%llu",
			(unsigned long long)
				replacement_credential->envelope.message_id);
		memcpy(replacement_credential->subject_public_key,
		       request->new_operational_public_key,
		       sizeof(replacement_credential->subject_public_key));
		replacement_credential->allowed_mlkem_mask =
			registrar->config.allowed_mlkem_mask;
		replacement_credential->allowed_mldsa_mask =
			registrar->config.allowed_mldsa_mask;
		replacement_credential->capabilities =
			record->granted_capabilities;
		replacement_credential->valid_from_ms = now_ms;
		replacement_credential->valid_until_ms =
			now_ms +
			registrar->config.credential_lifetime_ms;
		replacement_credential->issuance_epoch =
			record->credential_epoch + 1U;
		ret = copy_text(
			replacement_credential->product_class,
			sizeof(replacement_credential->product_class),
			record->product_class);
	}

	memset(authorization, 0, sizeof(*authorization));
	if (ret == 0) {
		ret = fill_envelope(
			registrar, record->device_id,
			PQCP_FLEET_MESSAGE_ROTATION_AUTHORIZATION,
			now_ms, registrar->config.credential_lifetime_ms,
			&authorization->envelope);
	}
	if (ret == 0) {
		memcpy(authorization->envelope.nonce,
		       request->envelope.nonce,
		       sizeof(authorization->envelope.nonce));
		(void)snprintf(
			authorization->authorization_id,
			sizeof(authorization->authorization_id),
			"rotation-%llu",
			(unsigned long long)
				authorization->envelope.message_id);
		ret = copy_text(
			authorization->replacement_credential_id,
			sizeof(authorization->replacement_credential_id),
			replacement_credential->credential_id);
	}
	if (ret == 0) {
		memcpy(authorization->old_key_fingerprint,
		       request->current_key_fingerprint,
		       sizeof(authorization->old_key_fingerprint));
		ret = pqcp_fleet_public_key_fingerprint(
			request->new_operational_public_key,
			authorization->new_key_fingerprint);
	}
	if (ret == 0) {
		authorization->valid_from_ms = now_ms;
		authorization->valid_until_ms =
			now_ms +
			registrar->config.credential_lifetime_ms;
		authorization->overlap_until_ms =
			now_ms + overlap_ms;
		ret = signer_for(
			registrar, &signer, &signer_context);
	}
	if (ret == 0) {
		ret = pqcp_fleet_credential_sign(
			replacement_credential, &signer, now_ms);
	}
	if (ret == 0) {
		ret = pqcp_fleet_rotation_authorization_sign(
			authorization, &signer, now_ms);
	}
	if (ret == 0) {
		memcpy(record->pending_public_key,
		       request->new_operational_public_key,
		       sizeof(record->pending_public_key));
		record->pending_credential =
			*replacement_credential;
		record->pending_key_present = true;
		record->pending_credential_present = true;
		record->last_sequence = request->envelope.sequence;
		record->state =
			PQCP_FLEET_REGISTRAR_DEVICE_ROTATING;
	}
	return ret;
}

int pqcp_fleet_registrar_commit_rotation(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id)
{
	struct pqcp_fleet_device_record *record =
		pqcp_fleet_registrar_find(registrar, device_id);

	if (record == NULL || !record->pending_key_present ||
	    !record->pending_credential_present ||
	    record->state !=
		    PQCP_FLEET_REGISTRAR_DEVICE_ROTATING) {
		return -EINVAL;
	}
	memcpy(record->operational_public_key, record->pending_public_key,
	       sizeof(record->operational_public_key));
	record->active_credential = record->pending_credential;
	record->credential_epoch =
		record->pending_credential.issuance_epoch;
	memset(record->pending_public_key, 0,
	       sizeof(record->pending_public_key));
	pqcp_runtime_secure_zero(
		&record->pending_credential,
		sizeof(record->pending_credential));
	record->pending_key_present = false;
	record->pending_credential_present = false;
	record->operational_key_present = true;
	record->state = PQCP_FLEET_REGISTRAR_DEVICE_OPERATIONAL;
	return 0;
}

int pqcp_fleet_registrar_decommission(
	struct pqcp_fleet_registrar *registrar,
	const char *device_id)
{
	struct pqcp_fleet_device_record *record =
		pqcp_fleet_registrar_find(registrar, device_id);

	if (record == NULL) return -ENOENT;
	record->state = PQCP_FLEET_REGISTRAR_DEVICE_DECOMMISSIONED;
	pqcp_runtime_secure_zero(
		record->operational_public_key,
		sizeof(record->operational_public_key));
	pqcp_runtime_secure_zero(
		record->pending_public_key,
		sizeof(record->pending_public_key));
	record->operational_key_present = false;
	record->pending_key_present = false;
	return 0;
}

int pqcp_fleet_registrar_audit(
	struct pqcp_fleet_registrar *registrar, uint64_t now_ms)
{
	if (registrar == NULL || !registrar->initialized ||
	    registrar->signer == NULL || !registrar->signer->active) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < registrar->capacity; ++index) {
		const struct pqcp_fleet_device_record *record =
			&registrar->records[index];

		if (!record->occupied) continue;
		if (!pqcp_runtime_internal_text_valid(
			    record->device_id, sizeof(record->device_id)) ||
		    record->state >
			    PQCP_FLEET_REGISTRAR_DEVICE_DECOMMISSIONED ||
		    (record->state ==
			     PQCP_FLEET_REGISTRAR_DEVICE_OPERATIONAL &&
		     (!record->operational_key_present ||
		      record->active_credential.valid_until_ms <= now_ms))) {
			return -EBADMSG;
		}
	}
	return 0;
}
