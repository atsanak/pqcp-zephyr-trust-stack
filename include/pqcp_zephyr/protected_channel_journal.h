/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Tamper-evident protected-channel event journal.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_PROTECTED_CHANNEL_JOURNAL_H_
#define PQCP_ZEPHYR_PROTECTED_CHANNEL_JOURNAL_H_

#include <pqcp_zephyr/protected_channel.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_CHANNEL_JOURNAL_DETAIL_MAX_CHARS 40U

enum pqcp_channel_journal_event {
	PQCP_CHANNEL_JOURNAL_TLS_READY = 1,
	PQCP_CHANNEL_JOURNAL_NEGOTIATION,
	PQCP_CHANNEL_JOURNAL_FRAME_SENT,
	PQCP_CHANNEL_JOURNAL_FRAME_RECEIVED,
	PQCP_CHANNEL_JOURNAL_KEM_ESTABLISHED,
	PQCP_CHANNEL_JOURNAL_PEER_AUTHENTICATED,
	PQCP_CHANNEL_JOURNAL_FINISHED_VERIFIED,
	PQCP_CHANNEL_JOURNAL_RECORD_SENT,
	PQCP_CHANNEL_JOURNAL_RECORD_RECEIVED,
	PQCP_CHANNEL_JOURNAL_REPLAY_REJECTED,
	PQCP_CHANNEL_JOURNAL_ALERT,
	PQCP_CHANNEL_JOURNAL_CLOSED,
	PQCP_CHANNEL_JOURNAL_FAULT,
};

struct pqcp_channel_journal_entry {
	uint32_t schema_version;
	uint64_t sequence;
	uint64_t timestamp_ms;
	uint64_t session_id;
	enum pqcp_channel_journal_event event;
	enum pqcp_channel_state state;
	enum pqcp_channel_frame_type frame_type;
	enum pqcp_channel_alert alert;
	uint64_t frame_sequence;
	uint32_t payload_bytes;
	int result;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	char detail[PQCP_CHANNEL_JOURNAL_DETAIL_MAX_CHARS];
	uint8_t transcript_hash[PQCP_CHANNEL_HASH_BYTES];
	uint8_t previous_digest[PQCP_CHANNEL_HASH_BYTES];
	uint8_t digest[PQCP_CHANNEL_HASH_BYTES];
};

struct pqcp_channel_journal_snapshot {
	uint32_t schema_version;
	uint64_t session_id;
	uint64_t first_sequence;
	uint64_t last_sequence;
	uint64_t total_entries;
	uint64_t overwritten_entries;
	uint32_t retained_entries;
	uint32_t alerts;
	uint32_t faults;
	uint32_t replay_rejections;
	uint8_t root_digest[PQCP_CHANNEL_HASH_BYTES];
	uint8_t snapshot_digest[PQCP_CHANNEL_HASH_BYTES];
};

struct pqcp_channel_journal {
	uint32_t schema_version;
	uint64_t session_id;
	struct pqcp_channel_journal_entry *entries;
	size_t capacity;
	size_t count;
	size_t head;
	uint64_t next_sequence;
	uint64_t overwritten_entries;
	uint32_t alert_count;
	uint32_t fault_count;
	uint32_t replay_rejection_count;
	uint8_t root_digest[PQCP_CHANNEL_HASH_BYTES];
	struct k_mutex lock;
};

int pqcp_channel_journal_init(
	struct pqcp_channel_journal *journal,
	uint64_t session_id,
	struct pqcp_channel_journal_entry *entries,
	size_t capacity);
int pqcp_channel_journal_append(
	struct pqcp_channel_journal *journal,
	const struct pqcp_channel *channel,
	enum pqcp_channel_journal_event event,
	enum pqcp_channel_frame_type frame_type,
	uint64_t frame_sequence,
	uint32_t payload_bytes,
	int result,
	const char *detail,
	uint64_t timestamp_ms);
int pqcp_channel_journal_snapshot(
	struct pqcp_channel_journal *journal,
	struct pqcp_channel_journal_snapshot *snapshot);
int pqcp_channel_journal_verify(
	struct pqcp_channel_journal *journal);
int pqcp_channel_journal_snapshot_verify(
	const struct pqcp_channel_journal_snapshot *snapshot);
const struct pqcp_channel_journal_entry *pqcp_channel_journal_get(
	const struct pqcp_channel_journal *journal,
	size_t logical_index);
int pqcp_channel_journal_emit(
	const struct pqcp_channel_journal_snapshot *snapshot);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_PROTECTED_CHANNEL_JOURNAL_H_ */
