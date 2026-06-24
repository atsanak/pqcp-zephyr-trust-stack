/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free durable fleet policy storage.
 */

#ifndef PQCP_ZEPHYR_FLEET_POLICY_STORE_H_
#define PQCP_ZEPHYR_FLEET_POLICY_STORE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_FLEET_POLICY_STORE_FORMAT_VERSION 1U
#define PQCP_FLEET_POLICY_STORE_BANK_COUNT 2U
#define PQCP_FLEET_POLICY_STORE_DIGEST_BYTES 32U
#define PQCP_FLEET_POLICY_STORE_ALIGNMENT 8U
#define PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES 116U
#define PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES 116U
#define PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES 16U
#define PQCP_FLEET_POLICY_STORE_BANK_PREFIX_BYTES 136U
#define PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES 80U
#define PQCP_FLEET_POLICY_STORE_MIN_BANK_BYTES \
	(PQCP_FLEET_POLICY_STORE_BANK_PREFIX_BYTES + \
	 PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES + \
	 PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES + 64U)

enum pqcp_fleet_policy_record_kind {
	PQCP_FLEET_POLICY_RECORD_POLICY = 1,
	PQCP_FLEET_POLICY_RECORD_EVENT,
	PQCP_FLEET_POLICY_RECORD_SNAPSHOT,
	PQCP_FLEET_POLICY_RECORD_REPAIR,
};

enum pqcp_fleet_policy_record_flag {
	PQCP_FLEET_POLICY_RECORD_CRITICAL = (1U << 0),
	PQCP_FLEET_POLICY_RECORD_CHECKPOINT = (1U << 1),
	PQCP_FLEET_POLICY_RECORD_REDACTED = (1U << 2),
};

enum pqcp_fleet_policy_bank_status {
	PQCP_FLEET_POLICY_BANK_EMPTY = 0,
	PQCP_FLEET_POLICY_BANK_VALID,
	PQCP_FLEET_POLICY_BANK_RECOVERABLE,
	PQCP_FLEET_POLICY_BANK_UNCOMMITTED,
	PQCP_FLEET_POLICY_BANK_CORRUPT,
	PQCP_FLEET_POLICY_BANK_ROLLBACK,
	PQCP_FLEET_POLICY_BANK_SCAN_LIMIT,
	PQCP_FLEET_POLICY_BANK_WORN,
	PQCP_FLEET_POLICY_BANK_QUARANTINED,
};

enum pqcp_fleet_policy_repair_flag {
	PQCP_FLEET_POLICY_REPAIR_REBUILD_REDUNDANCY = (1U << 0),
	PQCP_FLEET_POLICY_REPAIR_ERASE_UNRECOVERABLE = (1U << 1),
	PQCP_FLEET_POLICY_REPAIR_REQUIRE_SECURE_ERASE = (1U << 2),
};

enum pqcp_fleet_policy_repair_action {
	PQCP_FLEET_POLICY_REPAIR_NONE = 0,
	PQCP_FLEET_POLICY_REPAIR_RECOVERED = (1U << 0),
	PQCP_FLEET_POLICY_REPAIR_QUARANTINED = (1U << 1),
	PQCP_FLEET_POLICY_REPAIR_REBUILT = (1U << 2),
	PQCP_FLEET_POLICY_REPAIR_ERASED = (1U << 3),
	PQCP_FLEET_POLICY_REPAIR_SECURE_ERASED = (1U << 4),
	PQCP_FLEET_POLICY_REPAIR_REDUNDANCY_RESTORED = (1U << 5),
};

enum pqcp_fleet_policy_erase_flag {
	PQCP_FLEET_POLICY_ERASE_REQUIRE_SECURE = (1U << 0),
};

struct pqcp_fleet_policy_storage_backend {
	void *context;
	int (*read)(
		void *context, uint64_t offset,
		uint8_t *output, size_t length);
	int (*write)(
		void *context, uint64_t offset,
		const uint8_t *input, size_t length);
	int (*erase)(
		void *context, uint64_t offset, size_t length);
	int (*sync)(void *context);
	int (*secure_erase)(
		void *context, uint64_t offset, size_t length);
	int (*lock)(void *context);
	int (*unlock)(void *context);
	int (*read_rollback_floor)(
		void *context, uint64_t *generation,
		uint64_t *epoch);
	int (*advance_rollback_floor)(
		void *context, uint64_t generation,
		uint64_t epoch);
};

struct pqcp_fleet_policy_integrity_hooks {
	void *context;
	int (*checksum)(
		void *context, const uint8_t *data,
		size_t length, uint32_t *checksum);
	int (*hash_chain)(
		void *context,
		const uint8_t *canonical_prefix,
		size_t canonical_prefix_length,
		const uint8_t *payload,
		size_t payload_length,
		uint8_t digest[
			PQCP_FLEET_POLICY_STORE_DIGEST_BYTES]);
};

struct pqcp_fleet_policy_bank_region {
	uint64_t offset;
	size_t length;
};

struct pqcp_fleet_policy_wear_budget {
	uint64_t maximum_erase_cycles;
	uint64_t maximum_program_bytes;
};

struct pqcp_fleet_policy_store_config {
	struct pqcp_fleet_policy_storage_backend backend;
	struct pqcp_fleet_policy_integrity_hooks integrity;
	struct pqcp_fleet_policy_bank_region
		banks[PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	struct pqcp_fleet_policy_wear_budget wear;
	uint8_t *scratch;
	size_t scratch_capacity;
	size_t maximum_payload_bytes;
	size_t maximum_scan_records;
	size_t maximum_scan_bytes;
	uint64_t minimum_generation;
	uint64_t minimum_epoch;
	uint8_t erased_value;
	bool automatic_compaction;
};

struct pqcp_fleet_policy_record_info {
	enum pqcp_fleet_policy_record_kind kind;
	uint32_t flags;
	uint64_t generation;
	uint64_t epoch;
	uint64_t sequence;
	size_t payload_length;
	size_t storage_offset;
	uint32_t payload_checksum;
	uint8_t digest[PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
};

struct pqcp_fleet_policy_bank_info {
	enum pqcp_fleet_policy_bank_status status;
	uint64_t bank_generation;
	uint64_t previous_generation;
	uint64_t previous_epoch;
	uint64_t first_sequence;
	uint64_t last_sequence;
	uint64_t erase_cycles[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	uint64_t program_bytes[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	size_t append_offset;
	size_t records_scanned;
	size_t bytes_scanned;
	size_t corruption_offset;
	struct pqcp_fleet_policy_record_info policy;
	uint8_t previous_tail_digest[
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	uint8_t tail_digest[
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	bool header_valid;
	bool activated;
	bool tail_clean;
	bool policy_present;
	bool quarantined;
};

struct pqcp_fleet_policy_store {
	struct pqcp_fleet_policy_store_config config;
	struct pqcp_fleet_policy_bank_info
		bank[PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	struct pqcp_fleet_policy_record_info active_policy;
	uint8_t active_tail_digest[
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	uint64_t next_sequence;
	uint64_t rollback_generation_floor;
	uint64_t rollback_epoch_floor;
	uint64_t recovery_count;
	uint64_t compaction_count;
	uint64_t repair_count;
	size_t active_bank;
	uint32_t quarantine_mask;
	int last_recovery_error;
	bool initialized;
	bool policy_available;
	bool floor_sync_pending;
};

struct pqcp_fleet_policy_commit {
	const uint8_t *policy;
	size_t policy_length;
	uint64_t policy_epoch;
	uint64_t expected_generation;
	uint32_t flags;
};

struct pqcp_fleet_policy_journal_append {
	enum pqcp_fleet_policy_record_kind kind;
	const uint8_t *payload;
	size_t payload_length;
	uint32_t flags;
};

struct pqcp_fleet_policy_commit_result {
	struct pqcp_fleet_policy_record_info record;
	size_t bank;
	bool compacted;
	bool committed;
	bool rollback_floor_synchronized;
};

struct pqcp_fleet_policy_snapshot {
	uint32_t format_version;
	uint32_t quarantine_mask;
	uint64_t generation;
	uint64_t epoch;
	uint64_t next_sequence;
	uint64_t rollback_generation_floor;
	uint64_t rollback_epoch_floor;
	uint64_t recovery_count;
	uint64_t compaction_count;
	uint64_t repair_count;
	uint64_t erase_cycles[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	uint64_t program_bytes[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	size_t active_bank;
	size_t policy_length;
	size_t active_records;
	size_t active_bytes;
	size_t available_bytes;
	enum pqcp_fleet_policy_bank_status
		bank_status[PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	uint8_t policy_digest[
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	uint8_t journal_tail_digest[
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	uint8_t digest[PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	uint32_t checksum;
	bool policy_available;
	bool floor_sync_pending;
};

struct pqcp_fleet_policy_repair_report {
	enum pqcp_fleet_policy_bank_status
		before[PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	enum pqcp_fleet_policy_bank_status
		after[PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	uint32_t requested_flags;
	uint32_t actions;
	uint32_t quarantined_mask;
	uint32_t erased_mask;
	uint32_t rebuilt_mask;
	uint64_t recovered_generation;
	uint64_t recovered_epoch;
	uint64_t records_scanned;
	uint64_t bytes_scanned;
	uint64_t erase_cycles[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	uint64_t program_bytes[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	size_t active_bank;
	int recovery_result;
	int repair_result;
	bool policy_recovered;
	bool redundancy_available;
};

int pqcp_fleet_policy_store_init(
	struct pqcp_fleet_policy_store *store,
	const struct pqcp_fleet_policy_store_config *config);
int pqcp_fleet_policy_store_recover(
	struct pqcp_fleet_policy_store *store,
	struct pqcp_fleet_policy_repair_report *report);
int pqcp_fleet_policy_store_commit(
	struct pqcp_fleet_policy_store *store,
	const struct pqcp_fleet_policy_commit *commit,
	struct pqcp_fleet_policy_commit_result *result);
int pqcp_fleet_policy_store_load(
	struct pqcp_fleet_policy_store *store,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	struct pqcp_fleet_policy_record_info *record);
int pqcp_fleet_policy_journal_append(
	struct pqcp_fleet_policy_store *store,
	const struct pqcp_fleet_policy_journal_append *append,
	struct pqcp_fleet_policy_record_info *record);
int pqcp_fleet_policy_store_compact(
	struct pqcp_fleet_policy_store *store);
int pqcp_fleet_policy_storage_repair(
	struct pqcp_fleet_policy_store *store,
	uint32_t flags,
	struct pqcp_fleet_policy_repair_report *report);
int pqcp_fleet_policy_store_snapshot(
	struct pqcp_fleet_policy_store *store,
	struct pqcp_fleet_policy_snapshot *snapshot);
int pqcp_fleet_policy_snapshot_verify(
	const struct pqcp_fleet_policy_snapshot *snapshot);
int pqcp_fleet_policy_store_secure_erase(
	struct pqcp_fleet_policy_store *store,
	uint32_t flags,
	struct pqcp_fleet_policy_repair_report *report);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_FLEET_POLICY_STORE_H_ */
