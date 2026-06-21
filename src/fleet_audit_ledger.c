/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tamper-evident bounded audit ledger for device fleet operations.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_operations.h>

#include "runtime_internal.h"

#define FLEET_AUDIT_BODY_BYTES 256U

static bool event_valid(enum pqcp_fleet_audit_event event)
{
	return event > PQCP_FLEET_AUDIT_NONE &&
	       event < PQCP_FLEET_AUDIT_EVENT_COUNT;
}

static bool severity_valid(
	enum pqcp_fleet_audit_severity severity)
{
	return severity >= PQCP_FLEET_AUDIT_DEBUG &&
	       severity <= PQCP_FLEET_AUDIT_CRITICAL;
}

static bool digest_zero(
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_DIGEST_BYTES; ++index) {
		aggregate |= digest[index];
	}
	return aggregate == 0U;
}

static size_t append_u32(
	uint8_t *output,
	size_t offset,
	uint32_t value)
{
	pqcp_runtime_internal_write_u32(output + offset, value);
	return offset + 4U;
}

static size_t append_i32(
	uint8_t *output,
	size_t offset,
	int32_t value)
{
	pqcp_runtime_internal_write_u32(
		output + offset, (uint32_t)value);
	return offset + 4U;
}

static size_t append_u64(
	uint8_t *output,
	size_t offset,
	uint64_t value)
{
	pqcp_runtime_internal_write_u64(output + offset, value);
	return offset + 8U;
}

static size_t entry_body(
	const struct pqcp_fleet_audit_entry *entry,
	uint8_t output[FLEET_AUDIT_BODY_BYTES])
{
	size_t actor_length;
	size_t offset = 0U;

	if (entry == NULL || output == NULL ||
	    entry->schema_version !=
		    PQCP_FLEET_OPERATIONS_SCHEMA_VERSION ||
	    entry->sequence == 0U ||
	    entry->timestamp_ms == 0U ||
	    !event_valid(entry->event) ||
	    !severity_valid(entry->severity) ||
	    !pqcp_runtime_internal_text_valid(
		    entry->actor, sizeof(entry->actor)) ||
	    digest_zero(entry->payload_digest)) {
		return 0U;
	}
	memset(output, 0, FLEET_AUDIT_BODY_BYTES);
	memcpy(output + offset, "PQCP-FLEET-AUDIT-V1", 19U);
	offset += 19U;
	offset = append_u32(
		output, offset, entry->schema_version);
	offset = append_u64(output, offset, entry->sequence);
	offset = append_u64(
		output, offset, entry->timestamp_ms);
	offset = append_u32(
		output, offset, (uint32_t)entry->event);
	offset = append_u32(
		output, offset, (uint32_t)entry->severity);
	offset = append_u64(
		output, offset, entry->subject_id);
	offset = append_i32(output, offset, entry->result);
	actor_length = strnlen(
		entry->actor, sizeof(entry->actor));
	output[offset++] = (uint8_t)actor_length;
	memcpy(output + offset, entry->actor, actor_length);
	offset += actor_length;
	memcpy(output + offset, entry->payload_digest,
	       sizeof(entry->payload_digest));
	offset += sizeof(entry->payload_digest);
	memcpy(output + offset, entry->previous_digest,
	       sizeof(entry->previous_digest));
	offset += sizeof(entry->previous_digest);
	return offset <= FLEET_AUDIT_BODY_BYTES ? offset : 0U;
}

static int entry_digest(
	const struct pqcp_fleet_audit_entry *entry,
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES])
{
	uint8_t body[FLEET_AUDIT_BODY_BYTES];
	size_t length = entry_body(entry, body);
	int ret;

	if (length == 0U) {
		return -EINVAL;
	}
	ret = pqcp_runtime_internal_sha256(
		body, length, digest);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

int pqcp_fleet_audit_ledger_init(
	struct pqcp_fleet_audit_ledger *ledger,
	struct pqcp_fleet_audit_entry *entries,
	size_t capacity)
{
	if (ledger == NULL || entries == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(ledger, 0, sizeof(*ledger));
	memset(entries, 0, sizeof(*entries) * capacity);
	ledger->schema_version =
		PQCP_FLEET_OPERATIONS_SCHEMA_VERSION;
	ledger->entries = entries;
	ledger->capacity = capacity;
	ledger->next_sequence = 1U;
	k_mutex_init(&ledger->lock);
	ledger->initialized = true;
	return 0;
}

int pqcp_fleet_audit_append(
	struct pqcp_fleet_audit_ledger *ledger,
	enum pqcp_fleet_audit_event event,
	enum pqcp_fleet_audit_severity severity,
	const char *actor,
	uint64_t subject_id,
	int result,
	const uint8_t *payload,
	size_t payload_length,
	uint64_t now_ms,
	struct pqcp_fleet_audit_entry *entry)
{
	struct pqcp_fleet_audit_entry staged;
	int ret;

	if (ledger == NULL || !ledger->initialized ||
	    !event_valid(event) || !severity_valid(severity) ||
	    actor == NULL || subject_id == 0U ||
	    (payload == NULL && payload_length != 0U) ||
	    payload_length > PQCP_FLEET_AUDIT_PAYLOAD_MAX_BYTES ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	memset(&staged, 0, sizeof(staged));
	staged.schema_version =
		PQCP_FLEET_OPERATIONS_SCHEMA_VERSION;
	staged.timestamp_ms = now_ms;
	staged.event = event;
	staged.severity = severity;
	staged.subject_id = subject_id;
	staged.result = result;
	ret = pqcp_runtime_internal_copy_text(
		staged.actor, sizeof(staged.actor), actor);
	if (ret == 0) {
		ret = pqcp_runtime_internal_sha256(
			payload, payload_length,
			staged.payload_digest);
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			&staged, sizeof(staged));
		return ret;
	}
	ret = k_mutex_lock(&ledger->lock, K_FOREVER);
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			&staged, sizeof(staged));
		return ret;
	}
	staged.sequence = ledger->next_sequence++;
	if (staged.sequence == 0U) {
		staged.sequence = ledger->next_sequence++;
	}
	memcpy(staged.previous_digest,
	       ledger->chain_head,
	       sizeof(staged.previous_digest));
	staged.occupied = true;
	ret = entry_digest(&staged, staged.entry_digest);
	if (ret == 0) {
		if (ledger->count == ledger->capacity) {
			ledger->dropped_count++;
		} else {
			ledger->count++;
		}
		ledger->entries[ledger->next_index] = staged;
		ledger->next_index =
			(ledger->next_index + 1U) %
			ledger->capacity;
		memcpy(ledger->chain_head,
		       staged.entry_digest,
		       sizeof(ledger->chain_head));
		if (entry != NULL) {
			*entry = staged;
		}
	}
	(void)k_mutex_unlock(&ledger->lock);
	pqcp_runtime_secure_zero(&staged, sizeof(staged));
	return ret;
}

int pqcp_fleet_audit_find(
	struct pqcp_fleet_audit_ledger *ledger,
	uint64_t sequence,
	struct pqcp_fleet_audit_entry *entry)
{
	int ret;

	if (ledger == NULL || !ledger->initialized ||
	    sequence == 0U || entry == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&ledger->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < ledger->capacity;
	     ++index) {
		if (ledger->entries[index].occupied &&
		    ledger->entries[index].sequence == sequence) {
			*entry = ledger->entries[index];
			(void)k_mutex_unlock(&ledger->lock);
			return 0;
		}
	}
	(void)k_mutex_unlock(&ledger->lock);
	return -ENOENT;
}

static int next_sequence_index(
	const struct pqcp_fleet_audit_ledger *ledger,
	uint64_t after_sequence)
{
	uint64_t selected_sequence = UINT64_MAX;
	int selected = -1;

	for (size_t index = 0U; index < ledger->capacity;
	     ++index) {
		const struct pqcp_fleet_audit_entry *entry =
			&ledger->entries[index];

		if (!entry->occupied ||
		    entry->sequence <= after_sequence) {
			continue;
		}
		if (entry->sequence < selected_sequence) {
			selected_sequence = entry->sequence;
			selected = (int)index;
		}
	}
	return selected;
}

int pqcp_fleet_audit_verify(
	struct pqcp_fleet_audit_ledger *ledger)
{
	uint8_t previous[PQCP_FLEET_DIGEST_BYTES] = { 0 };
	uint8_t computed[PQCP_FLEET_DIGEST_BYTES];
	uint64_t previous_sequence = 0U;
	size_t verified = 0U;
	bool first = true;
	int index;
	int ret;

	if (ledger == NULL || !ledger->initialized ||
	    ledger->schema_version !=
		    PQCP_FLEET_OPERATIONS_SCHEMA_VERSION ||
	    ledger->entries == NULL || ledger->capacity == 0U ||
	    ledger->count > ledger->capacity ||
	    ledger->next_index >= ledger->capacity ||
	    ledger->next_sequence == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&ledger->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (;;) {
		index = next_sequence_index(
			ledger, previous_sequence);
		if (index < 0) {
			break;
		}
		const struct pqcp_fleet_audit_entry *entry =
			&ledger->entries[index];

		if (!first &&
		    memcmp(entry->previous_digest, previous,
			   sizeof(previous)) != 0) {
			ret = -EBADMSG;
			goto done;
		}
		ret = entry_digest(entry, computed);
		if (ret != 0 ||
		    memcmp(computed, entry->entry_digest,
			   sizeof(computed)) != 0) {
			ret = ret != 0 ? ret : -EBADMSG;
			goto done;
		}
		memcpy(previous, entry->entry_digest,
		       sizeof(previous));
		previous_sequence = entry->sequence;
		verified++;
		first = false;
		if (verified > ledger->capacity) {
			ret = -ELOOP;
			goto done;
		}
	}
	if (verified != ledger->count) {
		ret = -EBADMSG;
		goto done;
	}
	if (verified == 0U) {
		if (!digest_zero(ledger->chain_head)) {
			ret = -EBADMSG;
			goto done;
		}
	} else if (memcmp(previous, ledger->chain_head,
			  sizeof(previous)) != 0) {
		ret = -EBADMSG;
		goto done;
	}
	ret = 0;

done:
	(void)k_mutex_unlock(&ledger->lock);
	pqcp_runtime_secure_zero(previous, sizeof(previous));
	pqcp_runtime_secure_zero(computed, sizeof(computed));
	return ret;
}
