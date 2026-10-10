/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Bounded hash-chained operational journal for disconnected fleet devices.
 */

#ifndef PQCP_ZEPHYR_FLEET_JOURNAL_H_
#define PQCP_ZEPHYR_FLEET_JOURNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/fleet_protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_JOURNAL_SCHEMA_VERSION 1U
#define PQCP_FLEET_JOURNAL_DETAIL_MAX_BYTES 192U
#define PQCP_FLEET_JOURNAL_SUBJECT_MAX_CHARS 48U
#define PQCP_FLEET_JOURNAL_COMPONENT_MAX_CHARS 32U
#define PQCP_FLEET_JOURNAL_BATCH_MAX_ENTRIES 32U

enum pqcp_fleet_journal_kind {
	PQCP_FLEET_JOURNAL_NONE = 0,
	PQCP_FLEET_JOURNAL_BOOT,
	PQCP_FLEET_JOURNAL_ENROLLMENT_STARTED,
	PQCP_FLEET_JOURNAL_ENROLLMENT_COMPLETED,
	PQCP_FLEET_JOURNAL_POLICY_RECEIVED,
	PQCP_FLEET_JOURNAL_POLICY_APPLIED,
	PQCP_FLEET_JOURNAL_POLICY_REJECTED,
	PQCP_FLEET_JOURNAL_CREDENTIAL_ROTATION_STARTED,
	PQCP_FLEET_JOURNAL_CREDENTIAL_ROTATION_COMMITTED,
	PQCP_FLEET_JOURNAL_CREDENTIAL_ROTATION_ABORTED,
	PQCP_FLEET_JOURNAL_UPDATE_AUTHORIZED,
	PQCP_FLEET_JOURNAL_UPDATE_STAGED,
	PQCP_FLEET_JOURNAL_UPDATE_COMMITTED,
	PQCP_FLEET_JOURNAL_UPDATE_ROLLED_BACK,
	PQCP_FLEET_JOURNAL_REVOCATION_APPLIED,
	PQCP_FLEET_JOURNAL_ATTESTATION_EMITTED,
	PQCP_FLEET_JOURNAL_ATTESTATION_REJECTED,
	PQCP_FLEET_JOURNAL_COMMAND_ACCEPTED,
	PQCP_FLEET_JOURNAL_COMMAND_APPLIED,
	PQCP_FLEET_JOURNAL_COMMAND_REJECTED,
	PQCP_FLEET_JOURNAL_RECOVERY_ENTERED,
	PQCP_FLEET_JOURNAL_RECOVERY_COMPLETED,
	PQCP_FLEET_JOURNAL_QUARANTINE_ENTERED,
	PQCP_FLEET_JOURNAL_QUARANTINE_RELEASED,
	PQCP_FLEET_JOURNAL_CHANNEL_ESTABLISHED,
	PQCP_FLEET_JOURNAL_CHANNEL_CLOSED,
	PQCP_FLEET_JOURNAL_PEER_SYNCHRONIZED,
	PQCP_FLEET_JOURNAL_DECOMMISSIONED,
	PQCP_FLEET_JOURNAL_KIND_COUNT,
};

enum pqcp_fleet_journal_severity {
	PQCP_FLEET_JOURNAL_DEBUG = 0,
	PQCP_FLEET_JOURNAL_INFO,
	PQCP_FLEET_JOURNAL_NOTICE,
	PQCP_FLEET_JOURNAL_WARNING,
	PQCP_FLEET_JOURNAL_ERROR,
	PQCP_FLEET_JOURNAL_CRITICAL,
};

enum pqcp_fleet_journal_flag {
	PQCP_FLEET_JOURNAL_FLAG_SECURITY_RELEVANT = (1U << 0),
	PQCP_FLEET_JOURNAL_FLAG_REQUIRES_UPLOAD = (1U << 1),
	PQCP_FLEET_JOURNAL_FLAG_OPERATOR_VISIBLE = (1U << 2),
	PQCP_FLEET_JOURNAL_FLAG_RECOVERY_RELEVANT = (1U << 3),
	PQCP_FLEET_JOURNAL_FLAG_PRIVACY_REDACTED = (1U << 4),
	PQCP_FLEET_JOURNAL_FLAG_ACKNOWLEDGED = (1U << 5),
	PQCP_FLEET_JOURNAL_FLAG_CHECKPOINT = (1U << 6),
};

struct pqcp_fleet_journal_entry {
	uint32_t schema_version;
	uint64_t sequence;
	uint64_t timestamp_ms;
	uint64_t correlation_id;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	enum pqcp_fleet_journal_kind kind;
	enum pqcp_fleet_journal_severity severity;
	int32_t result;
	uint32_t reason;
	uint32_t flags;
	uint32_t detail_length;
	char subject[PQCP_FLEET_JOURNAL_SUBJECT_MAX_CHARS];
	char component[PQCP_FLEET_JOURNAL_COMPONENT_MAX_CHARS];
	uint8_t detail[PQCP_FLEET_JOURNAL_DETAIL_MAX_BYTES];
	uint8_t previous_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
	bool occupied;
};

struct pqcp_fleet_journal_append {
	uint64_t timestamp_ms;
	uint64_t correlation_id;
	uint64_t policy_epoch;
	uint64_t revocation_epoch;
	enum pqcp_fleet_journal_kind kind;
	enum pqcp_fleet_journal_severity severity;
	int32_t result;
	uint32_t reason;
	uint32_t flags;
	const char *subject;
	const char *component;
	const uint8_t *detail;
	size_t detail_length;
};

struct pqcp_fleet_journal_filter {
	uint64_t sequence_after;
	uint64_t sequence_before;
	uint64_t timestamp_after_ms;
	uint64_t timestamp_before_ms;
	uint64_t correlation_id;
	uint32_t required_flags;
	uint32_t forbidden_flags;
	enum pqcp_fleet_journal_kind kind;
	enum pqcp_fleet_journal_severity minimum_severity;
	const char *subject;
	const char *component;
};

struct pqcp_fleet_journal_cursor {
	uint64_t next_sequence;
	uint64_t observed_generation;
	bool initialized;
};

struct pqcp_fleet_journal_batch {
	struct pqcp_fleet_journal_entry
		entries[PQCP_FLEET_JOURNAL_BATCH_MAX_ENTRIES];
	size_t count;
	uint64_t first_sequence;
	uint64_t last_sequence;
	uint8_t first_previous_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t last_digest[PQCP_FLEET_DIGEST_BYTES];
	bool complete;
};

struct pqcp_fleet_journal_snapshot {
	uint32_t schema_version;
	uint64_t generation;
	uint64_t oldest_sequence;
	uint64_t newest_sequence;
	uint64_t acknowledged_through;
	uint64_t dropped_entries;
	uint64_t security_entries;
	uint64_t pending_upload_entries;
	size_t count;
	size_t capacity;
	uint8_t anchor_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t tail_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t digest[PQCP_FLEET_DIGEST_BYTES];
};

struct pqcp_fleet_journal {
	struct pqcp_fleet_journal_entry *entries;
	size_t capacity;
	size_t head;
	size_t count;
	uint64_t next_sequence;
	uint64_t generation;
	uint64_t acknowledged_through;
	uint64_t dropped_entries;
	uint64_t rejected_entries;
	uint64_t security_entries;
	uint64_t pending_upload_entries;
	uint8_t anchor_digest[PQCP_FLEET_DIGEST_BYTES];
	uint8_t tail_digest[PQCP_FLEET_DIGEST_BYTES];
	struct k_mutex lock;
	bool initialized;
};

int pqcp_fleet_journal_init(
	struct pqcp_fleet_journal *journal,
	struct pqcp_fleet_journal_entry *entries,
	size_t capacity,
	uint64_t first_sequence,
	const uint8_t anchor_digest[PQCP_FLEET_DIGEST_BYTES]);
int pqcp_fleet_journal_append(
	struct pqcp_fleet_journal *journal,
	const struct pqcp_fleet_journal_append *append,
	struct pqcp_fleet_journal_entry *committed);
int pqcp_fleet_journal_get(
	struct pqcp_fleet_journal *journal,
	uint64_t sequence,
	struct pqcp_fleet_journal_entry *entry);
int pqcp_fleet_journal_latest(
	struct pqcp_fleet_journal *journal,
	struct pqcp_fleet_journal_entry *entry);
int pqcp_fleet_journal_cursor_init(
	struct pqcp_fleet_journal *journal,
	struct pqcp_fleet_journal_cursor *cursor,
	uint64_t sequence_after);
int pqcp_fleet_journal_cursor_next(
	struct pqcp_fleet_journal *journal,
	struct pqcp_fleet_journal_cursor *cursor,
	const struct pqcp_fleet_journal_filter *filter,
	struct pqcp_fleet_journal_entry *entry);
int pqcp_fleet_journal_query(
	struct pqcp_fleet_journal *journal,
	const struct pqcp_fleet_journal_filter *filter,
	struct pqcp_fleet_journal_entry *output,
	size_t output_capacity,
	size_t *output_count);
int pqcp_fleet_journal_export_batch(
	struct pqcp_fleet_journal *journal,
	uint64_t sequence_after,
	size_t maximum_entries,
	bool upload_required_only,
	struct pqcp_fleet_journal_batch *batch);
int pqcp_fleet_journal_acknowledge(
	struct pqcp_fleet_journal *journal,
	uint64_t sequence,
	const uint8_t digest[PQCP_FLEET_DIGEST_BYTES],
	uint64_t *acknowledged_count);
int pqcp_fleet_journal_prune(
	struct pqcp_fleet_journal *journal,
	size_t maximum_to_prune,
	uint64_t *pruned_count);
int pqcp_fleet_journal_checkpoint(
	struct pqcp_fleet_journal *journal,
	uint64_t timestamp_ms,
	const char *component,
	struct pqcp_fleet_journal_entry *entry);
int pqcp_fleet_journal_snapshot(
	struct pqcp_fleet_journal *journal,
	struct pqcp_fleet_journal_snapshot *snapshot);
int pqcp_fleet_journal_verify(
	struct pqcp_fleet_journal *journal);
int pqcp_fleet_journal_entry_verify(
	const struct pqcp_fleet_journal_entry *entry);
int pqcp_fleet_journal_batch_verify(
	const struct pqcp_fleet_journal_batch *batch);
const char *pqcp_fleet_journal_kind_str(
	enum pqcp_fleet_journal_kind kind);
const char *pqcp_fleet_journal_severity_str(
	enum pqcp_fleet_journal_severity severity);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_JOURNAL_H_ */
