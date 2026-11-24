/*
 * SPDX-License-Identifier: MIT
 *
 * PSA Internal Trusted Storage backend for fleet ownership state.
 */

#include <errno.h>

#include <psa/internal_trusted_storage.h>

#include <pqcp_zephyr/fleet_store.h>

static int status_to_errno(psa_status_t status)
{
	switch (status) {
	case PSA_SUCCESS:
		return 0;
	case PSA_ERROR_DOES_NOT_EXIST:
		return -ENOENT;
	case PSA_ERROR_INSUFFICIENT_STORAGE:
		return -ENOSPC;
	case PSA_ERROR_NOT_PERMITTED:
		return -EACCES;
	case PSA_ERROR_INVALID_ARGUMENT:
		return -EINVAL;
	default:
		return -EIO;
	}
}

static int its_read(
	void *context, size_t slot,
	struct pqcp_fleet_store_record *record)
{
	struct pqcp_fleet_its_store *its = context;
	size_t length = 0U;
	psa_status_t status;

	if (its == NULL || record == NULL || slot >= 2U) {
		return -EINVAL;
	}
	status = psa_its_get(
		(psa_storage_uid_t)its->slot_uid[slot],
		0U, sizeof(*record), record, &length);
	if (status != PSA_SUCCESS) {
		return status_to_errno(status);
	}
	return length == sizeof(*record) ? 0 : -EBADMSG;
}

static int its_write(
	void *context, size_t slot,
	const struct pqcp_fleet_store_record *record)
{
	struct pqcp_fleet_its_store *its = context;

	if (its == NULL || record == NULL || slot >= 2U) {
		return -EINVAL;
	}
	return status_to_errno(psa_its_set(
		(psa_storage_uid_t)its->slot_uid[slot],
		sizeof(*record), record, PSA_STORAGE_FLAG_NONE));
}

static int its_erase(void *context, size_t slot)
{
	struct pqcp_fleet_its_store *its = context;

	if (its == NULL || slot >= 2U) {
		return -EINVAL;
	}
	return status_to_errno(psa_its_remove(
		(psa_storage_uid_t)its->slot_uid[slot]));
}

int pqcp_fleet_its_store_init(
	struct pqcp_fleet_store *store,
	struct pqcp_fleet_its_store *its,
	uint64_t first_uid)
{
	const struct pqcp_fleet_store_backend backend = {
		.context = its,
		.read_slot = its_read,
		.write_slot = its_write,
		.erase_slot = its_erase,
	};

	if (its == NULL || first_uid == 0U ||
	    first_uid == UINT64_MAX) {
		return -EINVAL;
	}
	its->slot_uid[0] = first_uid;
	its->slot_uid[1] = first_uid + 1U;
	return pqcp_fleet_store_init(store, &backend);
}
