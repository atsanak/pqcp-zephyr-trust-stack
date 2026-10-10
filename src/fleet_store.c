/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Two-slot atomic persistence for device fleet trust state.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_store.h>

#include "fleet_internal.h"

static bool bytes_nonzero(const uint8_t *value, size_t length)
{
	uint8_t combined = 0U;

	for (size_t index = 0U; index < length; ++index) {
		combined |= value[index];
	}
	return combined != 0U;
}

static int record_digest(
	const struct pqcp_fleet_store_record *record,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	struct pqcp_fleet_store_record copy;
	int ret;

	if (record == NULL || digest == NULL) {
		return -EINVAL;
	}
	copy = *record;
	memset(copy.digest, 0, sizeof(copy.digest));
	ret = pqcp_fleet_sha256(
		(const uint8_t *)&copy, sizeof(copy), digest);
	pqcp_runtime_secure_zero(&copy, sizeof(copy));
	return ret;
}

int pqcp_fleet_store_record_verify(
	const struct pqcp_fleet_store_record *record)
{
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	bool operational_state;
	int ret;

	if (record == NULL ||
	    record->schema_version !=
		    PQCP_FLEET_STORE_SCHEMA_VERSION ||
	    record->commit_generation == 0U ||
	    record->state > PQCP_FLEET_DEVICE_DECOMMISSIONED ||
	    record->boot_counter == 0U ||
	    record->pending_revocation_count >
		    PQCP_FLEET_MAX_REVOCATIONS ||
	    record->factory_key_valid !=
		    pqcp_runtime_key_handle_is_valid(
			    &record->factory_key) ||
	    !bytes_nonzero(record->registrar_public_key,
			   sizeof(record->registrar_public_key)) ||
	    (record->factory_key_valid &&
	     !bytes_nonzero(record->factory_fingerprint,
			    sizeof(record->factory_fingerprint)))) {
		return -EBADMSG;
	}
	operational_state =
		record->state >= PQCP_FLEET_DEVICE_OWNED &&
		record->state <= PQCP_FLEET_DEVICE_RECOVERY;
	if (operational_state &&
	    (!record->operational_key_valid ||
	     !pqcp_runtime_key_handle_is_valid(
		     &record->operational_key) ||
	     record->credential.envelope.type !=
		     PQCP_FLEET_MESSAGE_OPERATIONAL_CREDENTIAL ||
	     record->granted_capabilities == 0U)) {
		return -EBADMSG;
	}
	if (record->state >= PQCP_FLEET_DEVICE_OPERATIONAL &&
	    record->state <= PQCP_FLEET_DEVICE_RECOVERY &&
	    record->policy.envelope.type !=
		    PQCP_FLEET_MESSAGE_POLICY_BUNDLE) {
		return -EBADMSG;
	}
	if (record->state == PQCP_FLEET_DEVICE_ROTATING &&
	    (!record->pending_operational_key_valid ||
	     !pqcp_runtime_key_handle_is_valid(
		     &record->pending_operational_key))) {
		return -EBADMSG;
	}
	if (record->pending_operational_key_valid !=
	    pqcp_runtime_key_handle_is_valid(
		    &record->pending_operational_key)) {
		return -EBADMSG;
	}
	for (size_t index = 0U;
	     index < record->pending_revocation_count; ++index) {
		const struct pqcp_fleet_revocation_entry *entry =
			&record->pending_revocations[index];

		if (entry->kind < PQCP_FLEET_REVOKE_CREDENTIAL ||
		    entry->kind > PQCP_FLEET_REVOKE_DOMAIN ||
		    entry->effective_at_ms == 0U ||
		    strnlen(entry->subject_id,
			    sizeof(entry->subject_id)) == 0U ||
		    strnlen(entry->subject_id,
			    sizeof(entry->subject_id)) >=
			    sizeof(entry->subject_id)) {
			return -EBADMSG;
		}
	}
	ret = record_digest(record, digest);
	if (ret != 0) {
		return ret;
	}
	ret = memcmp(digest, record->digest, sizeof(digest)) == 0 ?
		0 : -EBADMSG;
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

int pqcp_fleet_store_init(
	struct pqcp_fleet_store *store,
	const struct pqcp_fleet_store_backend *backend)
{
	if (store == NULL || backend == NULL ||
	    backend->read_slot == NULL ||
	    backend->write_slot == NULL ||
	    backend->erase_slot == NULL) {
		return -EINVAL;
	}
	memset(store, 0, sizeof(*store));
	store->backend = *backend;
	store->initialized = true;
	return 0;
}

int pqcp_fleet_store_load(
	struct pqcp_fleet_store *store,
	struct pqcp_fleet_store_record *record)
{
	struct pqcp_fleet_store_record candidate[2];
	bool valid[2] = { false, false };

	if (store == NULL || !store->initialized ||
	    record == NULL) {
		return -EINVAL;
	}
	memset(candidate, 0, sizeof(candidate));
	for (size_t slot = 0U; slot < 2U; ++slot) {
		if (store->backend.read_slot(
			    store->backend.context, slot,
			    &candidate[slot]) == 0 &&
		    pqcp_fleet_store_record_verify(
			    &candidate[slot]) == 0) {
			valid[slot] = true;
		}
	}
	if (!valid[0] && !valid[1]) {
		return -ENOENT;
	}
	if (valid[0] && valid[1] &&
	    candidate[0].commit_generation ==
		    candidate[1].commit_generation &&
	    memcmp(&candidate[0], &candidate[1],
		   sizeof(candidate[0])) != 0) {
		pqcp_runtime_secure_zero(candidate, sizeof(candidate));
		return -EBADMSG;
	}
	if (valid[1] &&
	    (!valid[0] ||
	     candidate[1].commit_generation >
		     candidate[0].commit_generation)) {
		*record = candidate[1];
		store->active_slot = 1U;
	} else {
		*record = candidate[0];
		store->active_slot = 0U;
	}
	store->generation = record->commit_generation;
	pqcp_runtime_secure_zero(candidate, sizeof(candidate));
	return 0;
}

int pqcp_fleet_store_commit(
	struct pqcp_fleet_store *store,
	struct pqcp_fleet_store_record *record)
{
	struct pqcp_fleet_store_record staged;
	struct pqcp_fleet_store_record verify;
	size_t target;
	int ret;

	if (store == NULL || !store->initialized ||
	    record == NULL) {
		return -EINVAL;
	}
	if (store->generation == UINT64_MAX) {
		return -EOVERFLOW;
	}
	target = store->active_slot ^ 1U;
	staged = *record;
	staged.schema_version = PQCP_FLEET_STORE_SCHEMA_VERSION;
	staged.commit_generation = store->generation + 1U;
	memset(staged.digest, 0, sizeof(staged.digest));
	ret = record_digest(&staged, staged.digest);
	if (ret == 0) {
		ret = pqcp_fleet_store_record_verify(&staged);
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(&staged, sizeof(staged));
		return ret;
	}
	ret = store->backend.write_slot(
		store->backend.context, target, &staged);
	if (ret != 0) {
		pqcp_runtime_secure_zero(&staged, sizeof(staged));
		return ret;
	}
	memset(&verify, 0, sizeof(verify));
	ret = store->backend.read_slot(
		store->backend.context, target, &verify);
	if (ret == 0) {
		ret = pqcp_fleet_store_record_verify(&verify);
	}
	if (ret == 0 &&
	    verify.commit_generation !=
		    staged.commit_generation) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(&verify, sizeof(verify));
	if (ret != 0) {
		(void)store->backend.erase_slot(
			store->backend.context, target);
		pqcp_runtime_secure_zero(&staged, sizeof(staged));
		return ret;
	}
	store->active_slot = target;
	store->generation = staged.commit_generation;
	*record = staged;
	pqcp_runtime_secure_zero(&staged, sizeof(staged));
	return 0;
}

int pqcp_fleet_store_clear(struct pqcp_fleet_store *store)
{
	int first_error = 0;

	if (store == NULL || !store->initialized) {
		return -EINVAL;
	}
	for (size_t slot = 0U; slot < 2U; ++slot) {
		const int ret = store->backend.erase_slot(
			store->backend.context, slot);

		if (ret != 0 && ret != -ENOENT &&
		    first_error == 0) {
			first_error = ret;
		}
	}
	store->active_slot = 0U;
	store->generation = 0U;
	return first_error;
}

static int memory_read(
	void *context,
	size_t slot,
	struct pqcp_fleet_store_record *record)
{
	struct pqcp_fleet_memory_store *memory = context;

	if (memory == NULL || record == NULL ||
	    slot >= 2U || !memory->valid[slot]) {
		return -ENOENT;
	}
	*record = memory->slots[slot];
	return 0;
}

static int memory_write(
	void *context,
	size_t slot,
	const struct pqcp_fleet_store_record *record)
{
	struct pqcp_fleet_memory_store *memory = context;

	if (memory == NULL || record == NULL || slot >= 2U) {
		return -EINVAL;
	}
	memory->slots[slot] = *record;
	memory->valid[slot] = true;
	return 0;
}

static int memory_erase(void *context, size_t slot)
{
	struct pqcp_fleet_memory_store *memory = context;

	if (memory == NULL || slot >= 2U) {
		return -EINVAL;
	}
	pqcp_runtime_secure_zero(
		&memory->slots[slot],
		sizeof(memory->slots[slot]));
	memory->valid[slot] = false;
	return 0;
}

int pqcp_fleet_memory_store_init(
	struct pqcp_fleet_store *store,
	struct pqcp_fleet_memory_store *memory)
{
	const struct pqcp_fleet_store_backend backend = {
		.context = memory,
		.read_slot = memory_read,
		.write_slot = memory_write,
		.erase_slot = memory_erase,
	};

	if (memory == NULL) {
		return -EINVAL;
	}
	memset(memory, 0, sizeof(*memory));
	return pqcp_fleet_store_init(store, &backend);
}
