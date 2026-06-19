/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Fixed-capacity protected-channel supervisor.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/protected_channel_supervisor.h>

#include "runtime_internal.h"

#define SUPERVISOR_REPORT_DOMAIN UINT64_C(0x5051435053555031)

static bool policy_valid(
	const struct pqcp_channel_supervisor_policy *policy)
{
	return policy != NULL &&
	       policy->schema_version == PQCP_CHANNEL_SCHEMA_VERSION &&
	       policy->maximum_idle_ms != 0U &&
	       policy->maximum_lifetime_ms >= policy->maximum_idle_ms &&
	       policy->maximum_records != 0U &&
	       policy->maximum_plaintext_bytes != 0U &&
	       policy->maximum_sequence != 0U &&
	       policy->maximum_failures != 0U;
}

int pqcp_channel_supervisor_policy_default(
	struct pqcp_channel_supervisor_policy *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}
	*policy = (struct pqcp_channel_supervisor_policy) {
		.schema_version = PQCP_CHANNEL_SCHEMA_VERSION,
		.maximum_idle_ms = 60000U,
		.maximum_lifetime_ms = 3600000U,
		.maximum_records = 100000U,
		.maximum_plaintext_bytes = UINT64_C(1073741824),
		.maximum_sequence = UINT64_MAX - 1024U,
		.maximum_failures = 4U,
		.close_on_limit = true,
		.require_journal = true,
		.audit_each_tick = true,
	};
	return 0;
}

int pqcp_channel_supervisor_init(
	struct pqcp_channel_supervisor *supervisor,
	struct pqcp_channel_supervised_entry *entries,
	size_t capacity,
	const struct pqcp_channel_supervisor_policy *policy)
{
	struct pqcp_channel_supervisor_policy effective;

	if (supervisor == NULL || entries == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	if (policy == NULL) {
		if (pqcp_channel_supervisor_policy_default(
			    &effective) != 0) {
			return -EINVAL;
		}
		policy = &effective;
	}
	if (!policy_valid(policy)) {
		return -EINVAL;
	}
	memset(supervisor, 0, sizeof(*supervisor));
	memset(entries, 0, sizeof(*entries) * capacity);
	supervisor->schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	supervisor->entries = entries;
	supervisor->capacity = capacity;
	supervisor->policy = *policy;
	supervisor->next_registration_id = 1U;
	k_mutex_init(&supervisor->lock);
	return 0;
}

static struct pqcp_channel_supervised_entry *find_registration(
	struct pqcp_channel_supervisor *supervisor,
	uint64_t registration_id)
{
	for (size_t index = 0U; index < supervisor->capacity; ++index) {
		if (supervisor->entries[index].active &&
		    supervisor->entries[index].registration_id ==
			    registration_id) {
			return &supervisor->entries[index];
		}
	}
	return NULL;
}

static struct pqcp_channel_supervised_entry *find_free(
	struct pqcp_channel_supervisor *supervisor)
{
	for (size_t index = 0U; index < supervisor->capacity; ++index) {
		if (!supervisor->entries[index].active) {
			return &supervisor->entries[index];
		}
	}
	return NULL;
}

static bool channel_registered(
	const struct pqcp_channel_supervisor *supervisor,
	const struct pqcp_channel *channel)
{
	for (size_t index = 0U; index < supervisor->capacity; ++index) {
		if (supervisor->entries[index].active &&
		    supervisor->entries[index].channel == channel) {
			return true;
		}
	}
	return false;
}

int pqcp_channel_supervisor_register(
	struct pqcp_channel_supervisor *supervisor,
	struct pqcp_channel *channel,
	struct pqcp_channel_journal *journal,
	uint64_t now_ms,
	uint64_t *registration_id)
{
	struct pqcp_channel_supervised_entry *entry;
	int ret;

	if (supervisor == NULL || channel == NULL ||
	    registration_id == NULL || now_ms == 0U ||
	    channel->schema_version != PQCP_CHANNEL_SCHEMA_VERSION ||
	    channel->config.session_id == 0U ||
	    (supervisor->policy.require_journal && journal == NULL) ||
	    (journal != NULL &&
	     journal->session_id != channel->config.session_id)) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&supervisor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (channel_registered(supervisor, channel)) {
		(void)k_mutex_unlock(&supervisor->lock);
		return -EALREADY;
	}
	entry = find_free(supervisor);
	if (entry == NULL) {
		(void)k_mutex_unlock(&supervisor->lock);
		return -ENOSPC;
	}
	memset(entry, 0, sizeof(*entry));
	entry->schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	entry->registration_id = supervisor->next_registration_id++;
	if (supervisor->next_registration_id == 0U) {
		supervisor->next_registration_id = 1U;
	}
	entry->channel = channel;
	entry->journal = journal;
	entry->registered_at_ms = now_ms;
	entry->last_activity_at_ms = now_ms;
	entry->previous_frames_sent = channel->frames_sent;
	entry->previous_frames_received = channel->frames_received;
	entry->previous_bytes_sent =
		channel->application_bytes_sent;
	entry->previous_bytes_received =
		channel->application_bytes_received;
	entry->active = true;
	supervisor->registered_count++;
	*registration_id = entry->registration_id;
	if (journal != NULL) {
		(void)pqcp_channel_journal_append(
			journal, channel,
			PQCP_CHANNEL_JOURNAL_TLS_READY, 0,
			0U, 0U, 0, "supervisor-register", now_ms);
	}
	(void)k_mutex_unlock(&supervisor->lock);
	return 0;
}

int pqcp_channel_supervisor_touch(
	struct pqcp_channel_supervisor *supervisor,
	uint64_t registration_id,
	uint64_t now_ms)
{
	struct pqcp_channel_supervised_entry *entry;
	int ret;

	if (supervisor == NULL || registration_id == 0U ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&supervisor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	entry = find_registration(supervisor, registration_id);
	if (entry == NULL || now_ms < entry->last_activity_at_ms) {
		(void)k_mutex_unlock(&supervisor->lock);
		return -ENOENT;
	}
	entry->last_activity_at_ms = now_ms;
	entry->previous_frames_sent = entry->channel->frames_sent;
	entry->previous_frames_received =
		entry->channel->frames_received;
	entry->previous_bytes_sent =
		entry->channel->application_bytes_sent;
	entry->previous_bytes_received =
		entry->channel->application_bytes_received;
	(void)k_mutex_unlock(&supervisor->lock);
	return 0;
}

static int close_entry(
	struct pqcp_channel_supervisor *supervisor,
	struct pqcp_channel_supervised_entry *entry,
	uint32_t reason_mask,
	uint64_t now_ms)
{
	int ret = 0;

	entry->reason_mask |= reason_mask;
	entry->closing = true;
	if (entry->journal != NULL) {
		(void)pqcp_channel_journal_append(
			entry->journal, entry->channel,
			PQCP_CHANNEL_JOURNAL_CLOSED, 0,
			entry->channel->send_sequence, 0U,
			0, "supervisor-close", now_ms);
	}
	if (entry->channel->state != PQCP_CHANNEL_STATE_CLOSED) {
		ret = pqcp_channel_close(entry->channel);
	}
	entry->active = false;
	entry->closing = false;
	supervisor->closed_count++;
	return ret;
}

int pqcp_channel_supervisor_close(
	struct pqcp_channel_supervisor *supervisor,
	uint64_t registration_id,
	uint32_t reason_mask,
	uint64_t now_ms)
{
	struct pqcp_channel_supervised_entry *entry;
	int ret;

	if (supervisor == NULL || registration_id == 0U ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	if (reason_mask == 0U) {
		reason_mask =
			PQCP_CHANNEL_SUPERVISOR_REASON_ADMIN_CLOSE;
	}
	ret = k_mutex_lock(&supervisor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	entry = find_registration(supervisor, registration_id);
	if (entry == NULL) {
		(void)k_mutex_unlock(&supervisor->lock);
		return -ENOENT;
	}
	ret = close_entry(
		supervisor, entry, reason_mask, now_ms);
	(void)k_mutex_unlock(&supervisor->lock);
	return ret;
}

static uint32_t evaluate_limits(
	const struct pqcp_channel_supervisor *supervisor,
	const struct pqcp_channel_supervised_entry *entry,
	uint64_t now_ms)
{
	const struct pqcp_channel *channel = entry->channel;
	const uint64_t records =
		channel->frames_sent + channel->frames_received;
	const uint64_t bytes =
		channel->application_bytes_sent +
		channel->application_bytes_received;
	uint32_t reasons = 0U;

	if (now_ms - entry->last_activity_at_ms >
	    supervisor->policy.maximum_idle_ms) {
		reasons |=
			PQCP_CHANNEL_SUPERVISOR_REASON_IDLE_TIMEOUT;
	}
	if (now_ms - entry->registered_at_ms >
	    supervisor->policy.maximum_lifetime_ms) {
		reasons |= PQCP_CHANNEL_SUPERVISOR_REASON_LIFETIME;
	}
	if (records > supervisor->policy.maximum_records) {
		reasons |=
			PQCP_CHANNEL_SUPERVISOR_REASON_RECORD_LIMIT;
	}
	if (bytes > supervisor->policy.maximum_plaintext_bytes) {
		reasons |= PQCP_CHANNEL_SUPERVISOR_REASON_BYTE_LIMIT;
	}
	if (channel->failure_count >
	    supervisor->policy.maximum_failures) {
		reasons |=
			PQCP_CHANNEL_SUPERVISOR_REASON_FAILURE_LIMIT;
	}
	if (channel->send_sequence >
		    supervisor->policy.maximum_sequence ||
	    channel->receive_sequence >
		    supervisor->policy.maximum_sequence) {
		reasons |=
			PQCP_CHANNEL_SUPERVISOR_REASON_SEQUENCE_LIMIT;
	}
	if (supervisor->policy.audit_each_tick &&
	    pqcp_channel_audit(channel) != 0) {
		reasons |=
			PQCP_CHANNEL_SUPERVISOR_REASON_CHANNEL_AUDIT;
	}
	if (entry->journal != NULL &&
	    supervisor->policy.audit_each_tick &&
	    pqcp_channel_journal_verify(entry->journal) != 0) {
		reasons |=
			PQCP_CHANNEL_SUPERVISOR_REASON_JOURNAL_AUDIT;
	}
	return reasons;
}

static bool activity_changed(
	const struct pqcp_channel_supervised_entry *entry)
{
	return entry->channel->frames_sent !=
		       entry->previous_frames_sent ||
	       entry->channel->frames_received !=
		       entry->previous_frames_received ||
	       entry->channel->application_bytes_sent !=
		       entry->previous_bytes_sent ||
	       entry->channel->application_bytes_received !=
		       entry->previous_bytes_received;
}

static int report_hash(
	const struct pqcp_channel_supervisor_report *report,
	uint8_t output[PQCP_CHANNEL_HASH_BYTES])
{
	uint8_t buffer[96];
	size_t offset = 0U;

	memset(buffer, 0, sizeof(buffer));
	pqcp_runtime_internal_write_u64(
		buffer + offset, SUPERVISOR_REPORT_DOMAIN);
	offset += 8U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->capacity);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->active_channels);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->established_channels);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->closing_channels);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->failed_channels);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->audited_channels);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->closed_channels);
	offset += 4U;
	pqcp_runtime_internal_write_u32(
		buffer + offset, report->reason_mask);
	offset += 4U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, report->total_frames);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, report->total_plaintext_bytes);
	offset += 8U;
	pqcp_runtime_internal_write_u64(
		buffer + offset, report->evaluated_at_ms);
	offset += 8U;
	return pqcp_runtime_internal_sha256(buffer, offset, output);
}

int pqcp_channel_supervisor_tick(
	struct pqcp_channel_supervisor *supervisor,
	uint64_t now_ms,
	struct pqcp_channel_supervisor_report *report)
{
	int ret;

	if (supervisor == NULL || report == NULL || now_ms == 0U) {
		return -EINVAL;
	}
	memset(report, 0, sizeof(*report));
	report->schema_version = PQCP_CHANNEL_SCHEMA_VERSION;
	report->capacity = (uint32_t)supervisor->capacity;
	report->evaluated_at_ms = now_ms;
	ret = k_mutex_lock(&supervisor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < supervisor->capacity; ++index) {
		struct pqcp_channel_supervised_entry *entry =
			&supervisor->entries[index];
		uint32_t reasons;

		if (!entry->active) {
			continue;
		}
		report->active_channels++;
		if (entry->channel->established) {
			report->established_channels++;
		}
		if (entry->closing) {
			report->closing_channels++;
		}
		if (entry->channel->state ==
		    PQCP_CHANNEL_STATE_FAILED) {
			report->failed_channels++;
		}
		report->total_frames +=
			entry->channel->frames_sent +
			entry->channel->frames_received;
		report->total_plaintext_bytes +=
			entry->channel->application_bytes_sent +
			entry->channel->application_bytes_received;
		if (activity_changed(entry)) {
			entry->last_activity_at_ms = now_ms;
			entry->previous_frames_sent =
				entry->channel->frames_sent;
			entry->previous_frames_received =
				entry->channel->frames_received;
			entry->previous_bytes_sent =
				entry->channel->application_bytes_sent;
			entry->previous_bytes_received =
				entry->channel->application_bytes_received;
		}
		reasons = evaluate_limits(supervisor, entry, now_ms);
		report->audited_channels++;
		report->reason_mask |= reasons;
		if (reasons != 0U &&
		    supervisor->policy.close_on_limit) {
			(void)close_entry(
				supervisor, entry, reasons, now_ms);
			report->closed_channels++;
		}
	}
	(void)k_mutex_unlock(&supervisor->lock);
	return report_hash(report, report->digest);
}

int pqcp_channel_supervisor_audit(
	struct pqcp_channel_supervisor *supervisor)
{
	int ret;

	if (supervisor == NULL ||
	    supervisor->schema_version !=
		    PQCP_CHANNEL_SCHEMA_VERSION ||
	    supervisor->entries == NULL ||
	    supervisor->capacity == 0U ||
	    !policy_valid(&supervisor->policy)) {
		return -EBADMSG;
	}
	ret = k_mutex_lock(&supervisor->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < supervisor->capacity; ++index) {
		const struct pqcp_channel_supervised_entry *entry =
			&supervisor->entries[index];

		if (!entry->active) {
			continue;
		}
		if (entry->schema_version !=
			    PQCP_CHANNEL_SCHEMA_VERSION ||
		    entry->registration_id == 0U ||
		    entry->channel == NULL ||
		    entry->registered_at_ms == 0U ||
		    entry->last_activity_at_ms <
			    entry->registered_at_ms ||
		    (supervisor->policy.require_journal &&
		     entry->journal == NULL) ||
		    (entry->journal != NULL &&
		     entry->journal->session_id !=
			     entry->channel->config.session_id)) {
			(void)k_mutex_unlock(&supervisor->lock);
			return -EBADMSG;
		}
	}
	(void)k_mutex_unlock(&supervisor->lock);
	return 0;
}

int pqcp_channel_supervisor_report_verify(
	const struct pqcp_channel_supervisor_report *report)
{
	uint8_t expected[PQCP_CHANNEL_HASH_BYTES];

	if (report == NULL ||
	    report->schema_version != PQCP_CHANNEL_SCHEMA_VERSION ||
	    report->capacity == 0U ||
	    report->active_channels > report->capacity ||
	    report->established_channels > report->active_channels ||
	    report->closing_channels > report->active_channels ||
	    report->failed_channels > report->active_channels ||
	    report_hash(report, expected) != 0 ||
	    memcmp(expected, report->digest, sizeof(expected)) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_channel_supervisor_emit(
	const struct pqcp_channel_supervisor_report *report)
{
	char digest_hex[PQCP_RUNTIME_DIGEST_HEX_CHARS + 1U];

	if (pqcp_channel_supervisor_report_verify(report) != 0 ||
	    pqcp_runtime_internal_hex(
		    report->digest, sizeof(report->digest),
		    digest_hex, sizeof(digest_hex)) != 0) {
		return -EBADMSG;
	}
	printk("PQCP_CHANNEL_SUPERVISOR active=%u established=%u closing=%u failed=%u audited=%u closed=%u reasons=0x%08x frames=%llu bytes=%llu timestamp=%llu digest=%s\n",
	       report->active_channels,
	       report->established_channels,
	       report->closing_channels,
	       report->failed_channels,
	       report->audited_channels,
	       report->closed_channels,
	       report->reason_mask,
	       (unsigned long long)report->total_frames,
	       (unsigned long long)report->total_plaintext_bytes,
	       (unsigned long long)report->evaluated_at_ms,
	       digest_hex);
	return 0;
}
