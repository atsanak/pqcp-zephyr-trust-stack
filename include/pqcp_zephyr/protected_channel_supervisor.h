/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Multi-channel liveness, quota, and closure supervision.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_PROTECTED_CHANNEL_SUPERVISOR_H_
#define PQCP_ZEPHYR_PROTECTED_CHANNEL_SUPERVISOR_H_

#include <pqcp_zephyr/protected_channel_journal.h>

#ifdef __cplusplus
extern "C" {
#endif

enum pqcp_channel_supervisor_reason {
	PQCP_CHANNEL_SUPERVISOR_REASON_NONE = 0U,
	PQCP_CHANNEL_SUPERVISOR_REASON_IDLE_TIMEOUT = (1U << 0),
	PQCP_CHANNEL_SUPERVISOR_REASON_LIFETIME = (1U << 1),
	PQCP_CHANNEL_SUPERVISOR_REASON_RECORD_LIMIT = (1U << 2),
	PQCP_CHANNEL_SUPERVISOR_REASON_BYTE_LIMIT = (1U << 3),
	PQCP_CHANNEL_SUPERVISOR_REASON_FAILURE_LIMIT = (1U << 4),
	PQCP_CHANNEL_SUPERVISOR_REASON_SEQUENCE_LIMIT = (1U << 5),
	PQCP_CHANNEL_SUPERVISOR_REASON_CHANNEL_AUDIT = (1U << 6),
	PQCP_CHANNEL_SUPERVISOR_REASON_JOURNAL_AUDIT = (1U << 7),
	PQCP_CHANNEL_SUPERVISOR_REASON_ADMIN_CLOSE = (1U << 8),
};

struct pqcp_channel_supervisor_policy {
	uint32_t schema_version;
	uint64_t maximum_idle_ms;
	uint64_t maximum_lifetime_ms;
	uint64_t maximum_records;
	uint64_t maximum_plaintext_bytes;
	uint64_t maximum_sequence;
	uint32_t maximum_failures;
	bool close_on_limit;
	bool require_journal;
	bool audit_each_tick;
};

struct pqcp_channel_supervised_entry {
	uint32_t schema_version;
	uint64_t registration_id;
	struct pqcp_channel *channel;
	struct pqcp_channel_journal *journal;
	uint64_t registered_at_ms;
	uint64_t last_activity_at_ms;
	uint64_t previous_frames_sent;
	uint64_t previous_frames_received;
	uint64_t previous_bytes_sent;
	uint64_t previous_bytes_received;
	uint32_t reason_mask;
	bool active;
	bool closing;
};

struct pqcp_channel_supervisor_report {
	uint32_t schema_version;
	uint32_t capacity;
	uint32_t active_channels;
	uint32_t established_channels;
	uint32_t closing_channels;
	uint32_t failed_channels;
	uint32_t audited_channels;
	uint32_t closed_channels;
	uint32_t reason_mask;
	uint64_t total_frames;
	uint64_t total_plaintext_bytes;
	uint64_t evaluated_at_ms;
	uint8_t digest[PQCP_CHANNEL_HASH_BYTES];
};

struct pqcp_channel_supervisor {
	uint32_t schema_version;
	struct pqcp_channel_supervised_entry *entries;
	size_t capacity;
	struct pqcp_channel_supervisor_policy policy;
	uint64_t next_registration_id;
	uint64_t registered_count;
	uint64_t closed_count;
	struct k_mutex lock;
};

int pqcp_channel_supervisor_policy_default(
	struct pqcp_channel_supervisor_policy *policy);
int pqcp_channel_supervisor_init(
	struct pqcp_channel_supervisor *supervisor,
	struct pqcp_channel_supervised_entry *entries,
	size_t capacity,
	const struct pqcp_channel_supervisor_policy *policy);
int pqcp_channel_supervisor_register(
	struct pqcp_channel_supervisor *supervisor,
	struct pqcp_channel *channel,
	struct pqcp_channel_journal *journal,
	uint64_t now_ms,
	uint64_t *registration_id);
int pqcp_channel_supervisor_touch(
	struct pqcp_channel_supervisor *supervisor,
	uint64_t registration_id,
	uint64_t now_ms);
int pqcp_channel_supervisor_close(
	struct pqcp_channel_supervisor *supervisor,
	uint64_t registration_id,
	uint32_t reason_mask,
	uint64_t now_ms);
int pqcp_channel_supervisor_tick(
	struct pqcp_channel_supervisor *supervisor,
	uint64_t now_ms,
	struct pqcp_channel_supervisor_report *report);
int pqcp_channel_supervisor_audit(
	struct pqcp_channel_supervisor *supervisor);
int pqcp_channel_supervisor_report_verify(
	const struct pqcp_channel_supervisor_report *report);
int pqcp_channel_supervisor_emit(
	const struct pqcp_channel_supervisor_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_PROTECTED_CHANNEL_SUPERVISOR_H_ */
