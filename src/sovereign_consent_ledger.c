/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Fixed-capacity consent receipts with explicit tenant, controller, purpose,
 * classification, epoch, and validity bindings.
 */

#include "sovereign_privacy_internal.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

static ssize_t consent_index_locked(
	const struct pqcp_sovereign_consent_ledger *ledger,
	uint64_t consent_id)
{
	size_t index;

	for (index = 0U; index < ledger->capacity; ++index) {
		if (ledger->records[index].occupied &&
		    ledger->records[index].consent_id == consent_id) {
			return (ssize_t)index;
		}
	}
	return -1;
}

static ssize_t free_consent_index_locked(
	const struct pqcp_sovereign_consent_ledger *ledger)
{
	size_t index;

	for (index = 0U; index < ledger->capacity; ++index) {
		if (!ledger->records[index].occupied) {
			return (ssize_t)index;
		}
	}
	return -1;
}

static bool consent_fields_valid(
	const char *tenant_id,
	const char *subject_id,
	const char *controller_id,
	const char *purpose,
	uint32_t data_class_mask,
	uint64_t policy_epoch,
	const uint8_t terms_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	const uint8_t receipt_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms)
{
	uint32_t valid_mask =
		(1U << PQCP_SOVEREIGN_DATA_CLASS_COUNT) - 1U;

	return pqcp_sovereign_privacy_text_valid(
		       tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) &&
	       pqcp_sovereign_privacy_text_valid(
		       subject_id, PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) &&
	       pqcp_sovereign_privacy_text_valid(
		       controller_id, PQCP_SOVEREIGN_ID_MAX_CHARS) &&
	       pqcp_sovereign_privacy_text_valid(
		       purpose, PQCP_SOVEREIGN_LABEL_MAX_CHARS) &&
	       data_class_mask != 0U &&
	       (data_class_mask & ~valid_mask) == 0U &&
	       policy_epoch != 0U && now_ms != 0U &&
	       expires_at_ms > now_ms &&
	       !pqcp_sovereign_privacy_digest_zero(terms_digest) &&
	       !pqcp_sovereign_privacy_digest_zero(receipt_digest);
}

static bool active_consent_alias_locked(
	const struct pqcp_sovereign_consent_ledger *ledger,
	const char *tenant_id,
	const char *subject_id,
	const char *controller_id,
	const char *purpose,
	uint32_t data_class_mask,
	uint64_t now_ms)
{
	size_t index;

	for (index = 0U; index < ledger->capacity; ++index) {
		const struct pqcp_sovereign_consent_record *record =
			&ledger->records[index];

		if (!record->occupied ||
		    record->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    record->expires_at_ms <= now_ms ||
		    strcmp(record->tenant_id, tenant_id) != 0 ||
		    strcmp(record->subject_id, subject_id) != 0 ||
		    strcmp(record->controller_id, controller_id) != 0 ||
		    strcmp(record->purpose, purpose) != 0) {
			continue;
		}
		if ((record->data_class_mask & data_class_mask) != 0U) {
			return true;
		}
	}
	return false;
}

int pqcp_sovereign_consent_ledger_init(
	struct pqcp_sovereign_consent_ledger *ledger,
	struct pqcp_sovereign_consent_record *records,
	size_t capacity)
{
	if (ledger == NULL || records == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(ledger, 0, sizeof(*ledger));
	memset(records, 0, capacity * sizeof(*records));
	ledger->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	ledger->records = records;
	ledger->capacity = capacity;
	ledger->next_consent_id = 1U;
	k_mutex_init(&ledger->lock);
	ledger->initialized = true;
	return 0;
}

int pqcp_sovereign_consent_grant(
	struct pqcp_sovereign_consent_ledger *ledger,
	const char *tenant_id,
	const char *subject_id,
	const char *controller_id,
	const char *purpose,
	uint32_t data_class_mask,
	uint64_t policy_epoch,
	const uint8_t terms_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	const uint8_t receipt_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_consent_record **record)
{
	struct pqcp_sovereign_consent_record candidate;
	ssize_t index;
	int ret;

	if (ledger == NULL || !ledger->initialized || record == NULL ||
	    !consent_fields_valid(
		    tenant_id, subject_id, controller_id, purpose,
		    data_class_mask, policy_epoch, terms_digest,
		    receipt_digest, now_ms, expires_at_ms)) {
		return -EINVAL;
	}
	k_mutex_lock(&ledger->lock, K_FOREVER);
	if (active_consent_alias_locked(
		    ledger, tenant_id, subject_id, controller_id,
		    purpose, data_class_mask, now_ms)) {
		k_mutex_unlock(&ledger->lock);
		return -EALREADY;
	}
	index = free_consent_index_locked(ledger);
	if (index < 0) {
		k_mutex_unlock(&ledger->lock);
		return -ENOSPC;
	}
	if (ledger->next_consent_id == 0U ||
	    ledger->next_consent_id == UINT64_MAX) {
		k_mutex_unlock(&ledger->lock);
		return -EOVERFLOW;
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.consent_id = ledger->next_consent_id++;
	ret = pqcp_sovereign_privacy_copy_text(
		candidate.tenant_id, sizeof(candidate.tenant_id),
		tenant_id);
	if (ret == 0) {
		ret = pqcp_sovereign_privacy_copy_text(
			candidate.subject_id,
			sizeof(candidate.subject_id), subject_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_privacy_copy_text(
			candidate.controller_id,
			sizeof(candidate.controller_id), controller_id);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_privacy_copy_text(
			candidate.purpose, sizeof(candidate.purpose),
			purpose);
	}
	if (ret != 0) {
		k_mutex_unlock(&ledger->lock);
		return ret;
	}
	candidate.data_class_mask = data_class_mask;
	candidate.granted_at_ms = now_ms;
	candidate.expires_at_ms = expires_at_ms;
	candidate.policy_epoch = policy_epoch;
	memcpy(candidate.terms_digest, terms_digest,
	       sizeof(candidate.terms_digest));
	memcpy(candidate.receipt_digest, receipt_digest,
	       sizeof(candidate.receipt_digest));
	candidate.state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	candidate.occupied = true;
	ledger->records[index] = candidate;
	ledger->grant_count++;
	*record = &ledger->records[index];
	k_mutex_unlock(&ledger->lock);
	return 0;
}

int pqcp_sovereign_consent_authorize(
	struct pqcp_sovereign_consent_ledger *ledger,
	const char *tenant_id,
	const char *subject_id,
	const char *controller_id,
	const char *purpose,
	enum pqcp_sovereign_data_class data_class,
	uint64_t policy_epoch,
	uint64_t now_ms)
{
	size_t index;
	int ret = -EACCES;

	if (ledger == NULL || !ledger->initialized ||
	    !pqcp_sovereign_privacy_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    subject_id, PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    controller_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_text_valid(
		    purpose, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    !pqcp_sovereign_privacy_data_class_valid(data_class) ||
	    policy_epoch == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&ledger->lock, K_FOREVER);
	for (index = 0U; index < ledger->capacity; ++index) {
		const struct pqcp_sovereign_consent_record *record =
			&ledger->records[index];

		if (!record->occupied ||
		    record->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    strcmp(record->tenant_id, tenant_id) != 0 ||
		    strcmp(record->subject_id, subject_id) != 0 ||
		    strcmp(record->controller_id, controller_id) != 0 ||
		    strcmp(record->purpose, purpose) != 0 ||
		    (record->data_class_mask &
		     (1U << (uint32_t)data_class)) == 0U) {
			continue;
		}
		if (record->policy_epoch != policy_epoch) {
			ret = -ESTALE;
			continue;
		}
		if (record->granted_at_ms > now_ms ||
		    record->expires_at_ms <= now_ms ||
		    record->revoked_at_ms != 0U) {
			ret = -ETIME;
			continue;
		}
		if (pqcp_sovereign_privacy_digest_zero(
			    record->terms_digest) ||
		    pqcp_sovereign_privacy_digest_zero(
			    record->receipt_digest)) {
			ret = -EBADMSG;
			continue;
		}
		ret = 0;
		break;
	}
	k_mutex_unlock(&ledger->lock);
	return ret;
}

int pqcp_sovereign_consent_revoke(
	struct pqcp_sovereign_consent_ledger *ledger,
	uint64_t consent_id,
	uint64_t now_ms)
{
	struct pqcp_sovereign_consent_record *record;
	ssize_t index;

	if (ledger == NULL || !ledger->initialized ||
	    consent_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&ledger->lock, K_FOREVER);
	index = consent_index_locked(ledger, consent_id);
	if (index < 0) {
		k_mutex_unlock(&ledger->lock);
		return -ENOENT;
	}
	record = &ledger->records[index];
	if (record->state == PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
		k_mutex_unlock(&ledger->lock);
		return -EALREADY;
	}
	if (now_ms < record->granted_at_ms) {
		k_mutex_unlock(&ledger->lock);
		return -ETIME;
	}
	record->state = PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	record->revoked_at_ms = now_ms;
	ledger->revoke_count++;
	k_mutex_unlock(&ledger->lock);
	return 0;
}

int pqcp_sovereign_consent_tick(
	struct pqcp_sovereign_consent_ledger *ledger,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	size_t index;

	if (ledger == NULL || !ledger->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&ledger->lock, K_FOREVER);
	for (index = 0U; index < ledger->capacity; ++index) {
		struct pqcp_sovereign_consent_record *record =
			&ledger->records[index];

		if (!record->occupied ||
		    record->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    record->expires_at_ms > now_ms) {
			continue;
		}
		record->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
		expired++;
	}
	*expired_count = expired;
	k_mutex_unlock(&ledger->lock);
	return 0;
}

int pqcp_sovereign_consent_ledger_audit(
	struct pqcp_sovereign_consent_ledger *ledger)
{
	size_t index;
	size_t other;
	int ret = 0;

	if (ledger == NULL || !ledger->initialized ||
	    ledger->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    ledger->records == NULL || ledger->capacity == 0U ||
	    ledger->next_consent_id == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&ledger->lock, K_FOREVER);
	for (index = 0U; index < ledger->capacity && ret == 0;
	     ++index) {
		const struct pqcp_sovereign_consent_record *record =
			&ledger->records[index];

		if (!record->occupied) {
			continue;
		}
		if (record->schema_version !=
			    PQCP_SOVEREIGN_SCHEMA_VERSION ||
		    record->consent_id == 0U ||
		    !pqcp_sovereign_privacy_text_valid(
			    record->tenant_id,
			    sizeof(record->tenant_id)) ||
		    !pqcp_sovereign_privacy_text_valid(
			    record->subject_id,
			    sizeof(record->subject_id)) ||
		    !pqcp_sovereign_privacy_text_valid(
			    record->controller_id,
			    sizeof(record->controller_id)) ||
		    !pqcp_sovereign_privacy_text_valid(
			    record->purpose,
			    sizeof(record->purpose)) ||
		    record->data_class_mask == 0U ||
		    record->expires_at_ms <= record->granted_at_ms ||
		    pqcp_sovereign_privacy_digest_zero(
			    record->terms_digest) ||
		    pqcp_sovereign_privacy_digest_zero(
			    record->receipt_digest) ||
		    (record->state ==
			     PQCP_SOVEREIGN_LIFECYCLE_REVOKED &&
		     (record->revoked_at_ms < record->granted_at_ms ||
		      record->revoked_at_ms == 0U))) {
			ret = -EBADMSG;
			break;
		}
		for (other = index + 1U;
		     other < ledger->capacity; ++other) {
			if (ledger->records[other].occupied &&
			    ledger->records[other].consent_id ==
				    record->consent_id) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&ledger->lock);
	return ret;
}
