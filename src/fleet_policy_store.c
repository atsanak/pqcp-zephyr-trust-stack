/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free dual-bank fleet policy persistence and journal recovery.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_policy_store.h>

#include "fleet_internal.h"

#ifndef EDQUOT
#define EDQUOT ENOSPC
#endif

#ifndef ESTALE
#define ESTALE EAGAIN
#endif

#define BANK_MAGIC UINT32_C(0x50514642)
#define RECORD_MAGIC UINT32_C(0x50514652)
#define BANK_COMMIT_MAGIC UINT32_C(0x50424143)
#define RECORD_COMMIT_MAGIC UINT32_C(0x50524343)
#define BANK_FLAGS 0U
#define KNOWN_RECORD_FLAGS \
	(PQCP_FLEET_POLICY_RECORD_CRITICAL | \
	 PQCP_FLEET_POLICY_RECORD_CHECKPOINT | \
	 PQCP_FLEET_POLICY_RECORD_REDACTED)

struct bank_header {
	uint32_t bank_index;
	uint64_t bank_generation;
	uint64_t previous_generation;
	uint64_t previous_epoch;
	uint64_t first_sequence;
	uint64_t erase_cycles[PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	uint64_t program_bytes[PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	uint8_t previous_tail_digest[
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	uint32_t checksum;
};

struct record_header {
	enum pqcp_fleet_policy_record_kind kind;
	uint32_t flags;
	uint64_t generation;
	uint64_t epoch;
	uint64_t sequence;
	uint32_t payload_length;
	uint32_t payload_checksum;
	uint8_t previous_digest[
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	uint8_t digest[PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	uint32_t checksum;
};

static int recover_locked(
	struct pqcp_fleet_policy_store *store,
	struct pqcp_fleet_policy_repair_report *report);
static int erase_bank_locked(
	struct pqcp_fleet_policy_store *store,
	size_t bank, bool secure_required,
	bool *secure_used);
static int write_record_to_bank(
	struct pqcp_fleet_policy_store *store,
	size_t bank,
	struct pqcp_fleet_policy_bank_info *info,
	size_t offset,
	enum pqcp_fleet_policy_record_kind kind,
	uint32_t flags,
	uint64_t generation,
	uint64_t epoch,
	uint64_t sequence,
	const uint8_t *payload,
	size_t payload_length,
	const uint8_t previous_digest[
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES],
	struct pqcp_fleet_policy_record_info *record);
static int create_bank_with_policy_locked(
	struct pqcp_fleet_policy_store *store,
	size_t target,
	const uint8_t *policy,
	size_t policy_length,
	uint64_t generation,
	uint64_t epoch,
	uint32_t flags,
	struct pqcp_fleet_policy_record_info *record);
static int load_locked(
	struct pqcp_fleet_policy_store *store,
	uint8_t *output, size_t output_capacity,
	size_t *output_length,
	struct pqcp_fleet_policy_record_info *record);
static int compact_locked(
	struct pqcp_fleet_policy_store *store);
static int ensure_append_space_locked(
	struct pqcp_fleet_policy_store *store,
	size_t payload_length, bool *compacted);

static void secure_zero(void *value, size_t length)
{
	volatile uint8_t *bytes = value;

	while (length != 0U) {
		*bytes++ = 0U;
		length--;
	}
}

static uint16_t read_u16(const uint8_t *input)
{
	return ((uint16_t)input[0] << 8U) |
	       (uint16_t)input[1];
}

static uint32_t read_u32(const uint8_t *input)
{
	return ((uint32_t)input[0] << 24U) |
	       ((uint32_t)input[1] << 16U) |
	       ((uint32_t)input[2] << 8U) |
	       (uint32_t)input[3];
}

static uint64_t read_u64(const uint8_t *input)
{
	uint64_t value = 0U;

	for (size_t index = 0U; index < 8U; ++index) {
		value = (value << 8U) | input[index];
	}
	return value;
}

static void write_u16(uint8_t *output, uint16_t value)
{
	output[0] = (uint8_t)(value >> 8U);
	output[1] = (uint8_t)value;
}

static void write_u32(uint8_t *output, uint32_t value)
{
	output[0] = (uint8_t)(value >> 24U);
	output[1] = (uint8_t)(value >> 16U);
	output[2] = (uint8_t)(value >> 8U);
	output[3] = (uint8_t)value;
}

static void write_u64(uint8_t *output, uint64_t value)
{
	for (size_t index = 0U; index < 8U; ++index) {
		output[index] =
			(uint8_t)(value >> (56U - index * 8U));
	}
}

static uint64_t add_saturated(uint64_t left, uint64_t right)
{
	return UINT64_MAX - left < right ?
		UINT64_MAX : left + right;
}

static size_t add_size_saturated(size_t left, size_t right)
{
	return SIZE_MAX - left < right ?
		SIZE_MAX : left + right;
}

static size_t align_record(size_t value)
{
	const size_t mask =
		PQCP_FLEET_POLICY_STORE_ALIGNMENT - 1U;

	if (value > SIZE_MAX - mask) {
		return SIZE_MAX;
	}
	return (value + mask) & ~mask;
}

static bool all_value(
	const uint8_t *bytes, size_t length, uint8_t value)
{
	uint8_t difference = 0U;

	for (size_t index = 0U; index < length; ++index) {
		difference |= bytes[index] ^ value;
	}
	return difference == 0U;
}

static uint32_t crc32_default(
	const uint8_t *data, size_t length)
{
	uint32_t crc = UINT32_C(0xffffffff);

	for (size_t index = 0U; index < length; ++index) {
		crc ^= data[index];
		for (uint32_t bit = 0U; bit < 8U; ++bit) {
			const uint32_t mask =
				(uint32_t)-(int32_t)(crc & 1U);

			crc = (crc >> 1U) ^
			      (UINT32_C(0xedb88320) & mask);
		}
	}
	return ~crc;
}

static int checksum_bytes(
	const struct pqcp_fleet_policy_store *store,
	const uint8_t *data, size_t length,
	uint32_t *checksum)
{
	if (checksum == NULL ||
	    (length != 0U && data == NULL)) {
		return -EINVAL;
	}
	if (store->config.integrity.checksum != NULL) {
		return store->config.integrity.checksum(
			store->config.integrity.context,
			data, length, checksum);
	}
	*checksum = crc32_default(data, length);
	return 0;
}

static int hash_record(
	struct pqcp_fleet_policy_store *store,
	const uint8_t prefix[
		PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES],
	const uint8_t *payload, size_t payload_length,
	uint8_t digest[PQCP_FLEET_POLICY_STORE_DIGEST_BYTES])
{
	if (store->config.integrity.hash_chain != NULL) {
		return store->config.integrity.hash_chain(
			store->config.integrity.context,
			prefix,
			PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES,
			payload, payload_length, digest);
	}
	if (payload_length != 0U) {
		memmove(
			store->config.scratch +
				PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES,
			payload, payload_length);
	}
	memcpy(store->config.scratch, prefix,
	       PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES);
	return pqcp_fleet_sha256(
		store->config.scratch,
		PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES +
			payload_length,
		digest);
}

static int storage_lock(
	struct pqcp_fleet_policy_store *store)
{
	if (store->config.backend.lock == NULL) {
		return 0;
	}
	return store->config.backend.lock(
		store->config.backend.context);
}

static int storage_unlock(
	struct pqcp_fleet_policy_store *store, int result)
{
	int unlock_result = 0;

	if (store->config.backend.unlock != NULL) {
		unlock_result = store->config.backend.unlock(
			store->config.backend.context);
	}
	return result == 0 ? unlock_result : result;
}

static int storage_read(
	const struct pqcp_fleet_policy_store *store,
	size_t bank, size_t offset,
	uint8_t *output, size_t length)
{
	const struct pqcp_fleet_policy_bank_region *region;

	if (bank >= PQCP_FLEET_POLICY_STORE_BANK_COUNT ||
	    output == NULL) {
		return -EINVAL;
	}
	region = &store->config.banks[bank];
	if (offset > region->length ||
	    length > region->length - offset ||
	    region->offset > UINT64_MAX - offset) {
		return -EOVERFLOW;
	}
	return store->config.backend.read(
		store->config.backend.context,
		region->offset + offset, output, length);
}

static int storage_write(
	const struct pqcp_fleet_policy_store *store,
	size_t bank, size_t offset,
	const uint8_t *input, size_t length)
{
	const struct pqcp_fleet_policy_bank_region *region;

	if (bank >= PQCP_FLEET_POLICY_STORE_BANK_COUNT ||
	    input == NULL) {
		return -EINVAL;
	}
	region = &store->config.banks[bank];
	if (offset > region->length ||
	    length > region->length - offset ||
	    region->offset > UINT64_MAX - offset) {
		return -EOVERFLOW;
	}
	return store->config.backend.write(
		store->config.backend.context,
		region->offset + offset, input, length);
}

static int storage_sync(
	const struct pqcp_fleet_policy_store *store)
{
	return store->config.backend.sync(
		store->config.backend.context);
}

static bool kind_valid(enum pqcp_fleet_policy_record_kind kind)
{
	return kind >= PQCP_FLEET_POLICY_RECORD_POLICY &&
	       kind <= PQCP_FLEET_POLICY_RECORD_REPAIR;
}

static void encode_bank_header(
	const struct bank_header *header,
	uint8_t output[PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES])
{
	memset(output, 0,
	       PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES);
	write_u32(output, BANK_MAGIC);
	write_u16(output + 4U,
		  PQCP_FLEET_POLICY_STORE_FORMAT_VERSION);
	write_u16(
		output + 6U,
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES);
	write_u32(output + 8U, header->bank_index);
	write_u32(output + 12U, BANK_FLAGS);
	write_u64(output + 16U, header->bank_generation);
	write_u64(output + 24U, header->previous_generation);
	write_u64(output + 32U, header->previous_epoch);
	write_u64(output + 40U, header->first_sequence);
	write_u64(output + 48U, header->erase_cycles[0]);
	write_u64(output + 56U, header->erase_cycles[1]);
	write_u64(output + 64U, header->program_bytes[0]);
	write_u64(output + 72U, header->program_bytes[1]);
	memcpy(output + 80U, header->previous_tail_digest,
	       PQCP_FLEET_POLICY_STORE_DIGEST_BYTES);
	write_u32(output + 112U, header->checksum);
}

static int decode_bank_header(
	struct pqcp_fleet_policy_store *store,
	size_t bank,
	const uint8_t input[
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES],
	struct bank_header *header)
{
	uint32_t checksum;
	int ret;

	if (read_u32(input) != BANK_MAGIC ||
	    read_u16(input + 4U) !=
		    PQCP_FLEET_POLICY_STORE_FORMAT_VERSION ||
	    read_u16(input + 6U) !=
		    PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES ||
	    read_u32(input + 8U) != bank ||
	    read_u32(input + 12U) != BANK_FLAGS) {
		return -EBADMSG;
	}
	ret = checksum_bytes(store, input, 112U, &checksum);
	if (ret != 0) {
		return ret;
	}
	if (checksum != read_u32(input + 112U)) {
		return -EBADMSG;
	}
	memset(header, 0, sizeof(*header));
	header->bank_index = read_u32(input + 8U);
	header->bank_generation = read_u64(input + 16U);
	header->previous_generation =
		read_u64(input + 24U);
	header->previous_epoch = read_u64(input + 32U);
	header->first_sequence = read_u64(input + 40U);
	header->erase_cycles[0] = read_u64(input + 48U);
	header->erase_cycles[1] = read_u64(input + 56U);
	header->program_bytes[0] = read_u64(input + 64U);
	header->program_bytes[1] = read_u64(input + 72U);
	memcpy(header->previous_tail_digest, input + 80U,
	       sizeof(header->previous_tail_digest));
	header->checksum = checksum;
	if (header->bank_generation == 0U ||
	    header->first_sequence == 0U) {
		return -EBADMSG;
	}
	return 0;
}

static void encode_record_prefix(
	const struct record_header *header,
	uint8_t output[
		PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES])
{
	memset(output, 0,
	       PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES);
	write_u32(output, RECORD_MAGIC);
	write_u16(output + 4U,
		  PQCP_FLEET_POLICY_STORE_FORMAT_VERSION);
	write_u16(
		output + 6U,
		PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES);
	write_u32(output + 8U, (uint32_t)header->kind);
	write_u32(output + 12U, header->flags);
	write_u64(output + 16U, header->generation);
	write_u64(output + 24U, header->epoch);
	write_u64(output + 32U, header->sequence);
	write_u32(output + 40U, header->payload_length);
	write_u32(output + 44U, header->payload_checksum);
	memcpy(output + 48U, header->previous_digest,
	       sizeof(header->previous_digest));
}

static void encode_record_header(
	const struct record_header *header,
	uint8_t output[
		PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES])
{
	encode_record_prefix(header, output);
	memcpy(output + 80U, header->digest,
	       sizeof(header->digest));
	write_u32(output + 112U, header->checksum);
}

static int decode_record_header(
	struct pqcp_fleet_policy_store *store,
	const uint8_t input[
		PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES],
	struct record_header *header)
{
	uint32_t checksum;
	int ret;

	if (read_u32(input) != RECORD_MAGIC ||
	    read_u16(input + 4U) !=
		    PQCP_FLEET_POLICY_STORE_FORMAT_VERSION ||
	    read_u16(input + 6U) !=
		    PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES) {
		return -EBADMSG;
	}
	ret = checksum_bytes(store, input, 112U, &checksum);
	if (ret != 0) {
		return ret;
	}
	if (checksum != read_u32(input + 112U)) {
		return -EBADMSG;
	}
	memset(header, 0, sizeof(*header));
	header->kind = (enum pqcp_fleet_policy_record_kind)
		read_u32(input + 8U);
	header->flags = read_u32(input + 12U);
	header->generation = read_u64(input + 16U);
	header->epoch = read_u64(input + 24U);
	header->sequence = read_u64(input + 32U);
	header->payload_length = read_u32(input + 40U);
	header->payload_checksum = read_u32(input + 44U);
	memcpy(header->previous_digest, input + 48U,
	       sizeof(header->previous_digest));
	memcpy(header->digest, input + 80U,
	       sizeof(header->digest));
	header->checksum = checksum;
	if (!kind_valid(header->kind) ||
	    (header->flags & ~KNOWN_RECORD_FLAGS) != 0U ||
	    header->generation == 0U ||
	    header->sequence == 0U ||
	    (header->kind == PQCP_FLEET_POLICY_RECORD_POLICY &&
	     header->payload_length == 0U)) {
		return -EBADMSG;
	}
	return 0;
}

static void encode_commit_marker(
	uint32_t magic, uint32_t object_checksum,
	uint64_t sequence,
	uint8_t output[
		PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES])
{
	write_u32(output, magic);
	write_u32(output + 4U, object_checksum);
	write_u64(output + 8U, sequence);
}

static bool commit_marker_valid(
	const uint8_t input[
		PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES],
	uint32_t magic, uint32_t object_checksum,
	uint64_t sequence)
{
	return read_u32(input) == magic &&
	       read_u32(input + 4U) == object_checksum &&
	       read_u64(input + 8U) == sequence;
}

static void record_to_info(
	const struct record_header *header,
	size_t storage_offset,
	struct pqcp_fleet_policy_record_info *info)
{
	memset(info, 0, sizeof(*info));
	info->kind = header->kind;
	info->flags = header->flags;
	info->generation = header->generation;
	info->epoch = header->epoch;
	info->sequence = header->sequence;
	info->payload_length = header->payload_length;
	info->storage_offset = storage_offset;
	info->payload_checksum = header->payload_checksum;
	memcpy(info->digest, header->digest,
	       sizeof(info->digest));
}

static bool wear_exceeded(
	const struct pqcp_fleet_policy_store *store,
	const struct pqcp_fleet_policy_bank_info *info,
	size_t bank)
{
	return (store->config.wear.maximum_erase_cycles != 0U &&
		info->erase_cycles[bank] >
			store->config.wear.maximum_erase_cycles) ||
	       (store->config.wear.maximum_program_bytes != 0U &&
		info->program_bytes[bank] >
			store->config.wear.maximum_program_bytes);
}

static bool wear_allows(
	const struct pqcp_fleet_policy_store *store,
	const struct pqcp_fleet_policy_bank_info *info,
	size_t bank, uint64_t erase_increment,
	uint64_t program_increment)
{
	if (store->config.wear.maximum_erase_cycles != 0U &&
	    (info->erase_cycles[bank] >
		     store->config.wear.maximum_erase_cycles ||
	     erase_increment >
		     store->config.wear.maximum_erase_cycles -
			     info->erase_cycles[bank])) {
		return false;
	}
	if (store->config.wear.maximum_program_bytes != 0U &&
	    (info->program_bytes[bank] >
		     store->config.wear.maximum_program_bytes ||
	     program_increment >
		     store->config.wear.maximum_program_bytes -
			     info->program_bytes[bank])) {
		return false;
	}
	return true;
}

static int scan_bank(
	struct pqcp_fleet_policy_store *store,
	size_t bank,
	struct pqcp_fleet_policy_bank_info *info)
{
	uint8_t header_bytes[
		PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES];
	uint8_t marker[
		PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES];
	uint8_t prefix[
		PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES];
	uint8_t digest[PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	uint8_t previous[PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	struct bank_header bank_header;
	struct record_header record_header;
	uint64_t previous_sequence = 0U;
	uint64_t policy_generation = 0U;
	uint64_t policy_epoch = 0U;
	size_t offset;
	int ret;

	memset(info, 0, sizeof(*info));
	info->status = PQCP_FLEET_POLICY_BANK_EMPTY;
	ret = storage_read(
		store, bank, 0U, header_bytes,
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES);
	if (ret != 0) {
		return ret;
	}
	info->bytes_scanned =
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES;
	if (all_value(
		    header_bytes,
		    PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES,
		    store->config.erased_value)) {
		info->append_offset =
			PQCP_FLEET_POLICY_STORE_BANK_PREFIX_BYTES;
		info->tail_clean = true;
		return 0;
	}
	ret = decode_bank_header(
		store, bank, header_bytes, &bank_header);
	if (ret != 0) {
		info->status = PQCP_FLEET_POLICY_BANK_CORRUPT;
		info->corruption_offset = 0U;
		return ret == -EBADMSG ? 0 : ret;
	}
	info->header_valid = true;
	info->bank_generation =
		bank_header.bank_generation;
	info->previous_generation =
		bank_header.previous_generation;
	info->previous_epoch = bank_header.previous_epoch;
	info->first_sequence = bank_header.first_sequence;
	memcpy(info->erase_cycles, bank_header.erase_cycles,
	       sizeof(info->erase_cycles));
	memcpy(info->program_bytes, bank_header.program_bytes,
	       sizeof(info->program_bytes));
	memcpy(info->previous_tail_digest,
	       bank_header.previous_tail_digest,
	       sizeof(info->previous_tail_digest));
	info->program_bytes[bank] = add_saturated(
		info->program_bytes[bank],
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES);
	ret = storage_read(
		store, bank,
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES,
		marker, sizeof(marker));
	if (ret != 0) {
		return ret;
	}
	info->bytes_scanned += sizeof(marker);
	if (all_value(marker, sizeof(marker),
		      store->config.erased_value)) {
		info->status =
			PQCP_FLEET_POLICY_BANK_UNCOMMITTED;
		return 0;
	}
	if (!commit_marker_valid(
		    marker, BANK_COMMIT_MAGIC,
		    bank_header.checksum,
		    bank_header.bank_generation)) {
		info->status = PQCP_FLEET_POLICY_BANK_CORRUPT;
		info->corruption_offset =
			PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES;
		return 0;
	}
	info->activated = true;
	info->program_bytes[bank] = add_saturated(
		info->program_bytes[bank], sizeof(marker));
	memcpy(previous, bank_header.previous_tail_digest,
	       sizeof(previous));
	offset = PQCP_FLEET_POLICY_STORE_BANK_PREFIX_BYTES;
	while (offset <
	       store->config.banks[bank].length) {
		size_t committed_bytes;
		size_t next_offset;
		size_t marker_offset;
		uint32_t payload_checksum;

		if (info->records_scanned >=
			    store->config.maximum_scan_records ||
		    info->bytes_scanned >=
			    store->config.maximum_scan_bytes) {
			info->status =
				PQCP_FLEET_POLICY_BANK_SCAN_LIMIT;
			info->append_offset = offset;
			return 0;
		}
		if (store->config.banks[bank].length - offset <
		    PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES) {
			info->tail_clean = true;
			info->append_offset = offset;
			break;
		}
		if (PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES >
		    store->config.maximum_scan_bytes -
			    info->bytes_scanned) {
			info->status =
				PQCP_FLEET_POLICY_BANK_SCAN_LIMIT;
			info->append_offset = offset;
			return 0;
		}
		ret = storage_read(
			store, bank, offset, header_bytes,
			PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES);
		if (ret != 0) {
			return ret;
		}
		info->bytes_scanned +=
			PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES;
		if (all_value(
			    header_bytes,
			    PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES,
			    store->config.erased_value)) {
			info->tail_clean = true;
			info->append_offset = offset;
			break;
		}
		ret = decode_record_header(
			store, header_bytes, &record_header);
		if (ret != 0) {
			if (ret != -EBADMSG) {
				return ret;
			}
			info->status =
				PQCP_FLEET_POLICY_BANK_RECOVERABLE;
			info->corruption_offset = offset;
			info->append_offset = offset;
			break;
		}
		if (record_header.payload_length >
			    store->config.maximum_payload_bytes ||
		    record_header.payload_length >
			    store->config.banks[bank].length -
				    offset -
				    PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES ||
		    (size_t)record_header.payload_length +
				    PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES >
			    store->config.banks[bank].length -
				    offset -
				    PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES) {
			info->status =
				PQCP_FLEET_POLICY_BANK_CORRUPT;
			info->corruption_offset = offset;
			info->append_offset = offset;
			break;
		}
		committed_bytes =
			PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES +
			(size_t)record_header.payload_length +
			PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES;
		next_offset = align_record(offset + committed_bytes);
		if (next_offset == SIZE_MAX ||
		    next_offset >
			    store->config.banks[bank].length) {
			info->status =
				PQCP_FLEET_POLICY_BANK_CORRUPT;
			info->corruption_offset = offset;
			info->append_offset = offset;
			break;
		}
		if (committed_bytes -
			    PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES >
		    store->config.maximum_scan_bytes -
			    info->bytes_scanned) {
			info->status =
				PQCP_FLEET_POLICY_BANK_SCAN_LIMIT;
			info->append_offset = offset;
			return 0;
		}
		if (record_header.payload_length != 0U) {
			ret = storage_read(
				store, bank,
				offset +
					PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES,
				store->config.scratch +
					PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES,
				record_header.payload_length);
			if (ret != 0) {
				return ret;
			}
		}
		info->bytes_scanned += record_header.payload_length;
		ret = checksum_bytes(
			store,
			store->config.scratch +
				PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES,
			record_header.payload_length,
			&payload_checksum);
		if (ret != 0) {
			return ret;
		}
		marker_offset =
			offset +
			PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES +
			record_header.payload_length;
		ret = storage_read(
			store, bank, marker_offset,
			marker, sizeof(marker));
		if (ret != 0) {
			return ret;
		}
		info->bytes_scanned += sizeof(marker);
		if (all_value(marker, sizeof(marker),
			      store->config.erased_value)) {
			info->status =
				PQCP_FLEET_POLICY_BANK_RECOVERABLE;
			info->corruption_offset = offset;
			info->append_offset = offset;
			break;
		}
		if (!commit_marker_valid(
			    marker, RECORD_COMMIT_MAGIC,
			    record_header.checksum,
			    record_header.sequence) ||
		    payload_checksum !=
			    record_header.payload_checksum ||
		    memcmp(record_header.previous_digest,
			   previous, sizeof(previous)) != 0 ||
		    (previous_sequence == 0U &&
		     record_header.sequence !=
			     bank_header.first_sequence) ||
		    (previous_sequence != 0U &&
		     (previous_sequence == UINT64_MAX ||
		      record_header.sequence !=
			      previous_sequence + 1U))) {
			info->status =
				PQCP_FLEET_POLICY_BANK_CORRUPT;
			info->corruption_offset = offset;
			info->append_offset = offset;
			break;
		}
		encode_record_prefix(&record_header, prefix);
		ret = hash_record(
			store, prefix,
			store->config.scratch +
				PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES,
			record_header.payload_length, digest);
		if (ret != 0) {
			return ret;
		}
		if (memcmp(digest, record_header.digest,
			   sizeof(digest)) != 0 ||
		    (info->records_scanned == 0U &&
		     (record_header.kind !=
			      PQCP_FLEET_POLICY_RECORD_POLICY ||
		      record_header.generation <
			      bank_header.previous_generation ||
		      record_header.epoch <
			      bank_header.previous_epoch)) ||
		    (record_header.kind !=
			     PQCP_FLEET_POLICY_RECORD_POLICY &&
		     (!info->policy_present ||
		      record_header.generation !=
			      policy_generation ||
		      record_header.epoch != policy_epoch)) ||
		    (record_header.kind ==
			     PQCP_FLEET_POLICY_RECORD_POLICY &&
		     info->policy_present &&
		     (record_header.generation <=
			      policy_generation ||
		      record_header.epoch < policy_epoch))) {
			info->status =
				PQCP_FLEET_POLICY_BANK_CORRUPT;
			info->corruption_offset = offset;
			info->append_offset = offset;
			break;
		}
		info->records_scanned++;
		info->program_bytes[bank] = add_saturated(
			info->program_bytes[bank],
			committed_bytes);
		previous_sequence = record_header.sequence;
		info->last_sequence = record_header.sequence;
		memcpy(previous, record_header.digest,
		       sizeof(previous));
		memcpy(info->tail_digest, record_header.digest,
		       sizeof(info->tail_digest));
		if (record_header.kind ==
		    PQCP_FLEET_POLICY_RECORD_POLICY) {
			policy_generation =
				record_header.generation;
			policy_epoch = record_header.epoch;
			record_to_info(
				&record_header, offset,
				&info->policy);
			info->policy_present = true;
		}
		offset = next_offset;
		info->append_offset = offset;
	}
	secure_zero(
		store->config.scratch,
		store->config.scratch_capacity);
	secure_zero(digest, sizeof(digest));
	if (info->status ==
		    PQCP_FLEET_POLICY_BANK_RECOVERABLE ||
	    info->status ==
		    PQCP_FLEET_POLICY_BANK_CORRUPT) {
		return 0;
	}
	if (!info->policy_present) {
		info->status = PQCP_FLEET_POLICY_BANK_CORRUPT;
		info->corruption_offset =
			PQCP_FLEET_POLICY_STORE_BANK_PREFIX_BYTES;
		return 0;
	}
	info->status = wear_exceeded(store, info, bank) ?
		PQCP_FLEET_POLICY_BANK_WORN :
		PQCP_FLEET_POLICY_BANK_VALID;
	return 0;
}

static bool bank_policy_usable(
	const struct pqcp_fleet_policy_bank_info *info)
{
	return info->policy_present &&
	       (info->status == PQCP_FLEET_POLICY_BANK_VALID ||
		info->status ==
			PQCP_FLEET_POLICY_BANK_RECOVERABLE ||
		info->status == PQCP_FLEET_POLICY_BANK_WORN);
}

static void report_fill(
	const struct pqcp_fleet_policy_store *store,
	struct pqcp_fleet_policy_repair_report *report)
{
	if (report == NULL) {
		return;
	}
	report->records_scanned = 0U;
	report->bytes_scanned = 0U;
	report->quarantined_mask = store->quarantine_mask;
	report->active_bank = store->active_bank;
	report->policy_recovered = store->policy_available;
	report->recovered_generation =
		store->policy_available ?
			store->active_policy.generation : 0U;
	report->recovered_epoch =
		store->policy_available ?
			store->active_policy.epoch : 0U;
	report->redundancy_available =
		bank_policy_usable(&store->bank[0]) &&
		bank_policy_usable(&store->bank[1]);
	for (size_t bank = 0U;
	     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
	     ++bank) {
		report->after[bank] = store->bank[bank].status;
		report->records_scanned +=
			store->bank[bank].records_scanned;
		report->bytes_scanned +=
			store->bank[bank].bytes_scanned;
		report->erase_cycles[bank] =
			store->bank[bank].erase_cycles[bank];
		report->program_bytes[bank] =
			store->bank[bank].program_bytes[bank];
	}
}

static int read_rollback_floor_locked(
	struct pqcp_fleet_policy_store *store)
{
	uint64_t generation =
		store->config.minimum_generation;
	uint64_t epoch = store->config.minimum_epoch;
	int ret;

	if (store->config.backend.read_rollback_floor != NULL) {
		uint64_t backend_generation = 0U;
		uint64_t backend_epoch = 0U;

		ret = store->config.backend.read_rollback_floor(
			store->config.backend.context,
			&backend_generation, &backend_epoch);
		if (ret != 0 && ret != -ENOENT) {
			return ret;
		}
		if (ret == 0) {
			if (backend_generation > generation) {
				generation = backend_generation;
			}
			if (backend_epoch > epoch) {
				epoch = backend_epoch;
			}
		}
	}
	store->rollback_generation_floor = generation;
	store->rollback_epoch_floor = epoch;
	return 0;
}

static bool config_valid(
	const struct pqcp_fleet_policy_store_config *config)
{
	uint64_t end[2];
	size_t minimum_scan;
	size_t scratch_required;

	if (config == NULL ||
	    config->backend.read == NULL ||
	    config->backend.write == NULL ||
	    config->backend.erase == NULL ||
	    config->backend.sync == NULL ||
	    (config->backend.lock == NULL) !=
		    (config->backend.unlock == NULL) ||
	    config->scratch == NULL ||
	    config->maximum_payload_bytes == 0U ||
	    config->maximum_scan_records < 2U ||
	    config->maximum_scan_bytes <
		    PQCP_FLEET_POLICY_STORE_BANK_PREFIX_BYTES ||
	    config->maximum_payload_bytes >
		    UINT32_MAX ||
	    config->maximum_payload_bytes >
		    SIZE_MAX -
			    PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES) {
		return false;
	}
	scratch_required =
		config->maximum_payload_bytes +
		PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES;
	if (config->scratch_capacity < scratch_required) {
		return false;
	}
	if (config->maximum_payload_bytes >
	    SIZE_MAX -
		    PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES -
		    PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES -
		    PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES * 2U -
		    PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES * 2U) {
		return false;
	}
	minimum_scan =
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES +
		PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES +
		PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES * 2U +
		PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES * 2U +
		config->maximum_payload_bytes;
	if (config->maximum_scan_bytes < minimum_scan) {
		return false;
	}
	for (size_t bank = 0U;
	     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
	     ++bank) {
		size_t required;

		if (config->banks[bank].length <
			    PQCP_FLEET_POLICY_STORE_MIN_BANK_BYTES ||
		    config->banks[bank].offset >
			    UINT64_MAX -
				    config->banks[bank].length ||
		    config->maximum_payload_bytes >
			    SIZE_MAX -
				    PQCP_FLEET_POLICY_STORE_BANK_PREFIX_BYTES -
				    PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES -
				    PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES) {
			return false;
		}
		required = align_record(
			PQCP_FLEET_POLICY_STORE_BANK_PREFIX_BYTES +
			PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES +
			config->maximum_payload_bytes +
			PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES);
		if (required != SIZE_MAX) {
			required = align_record(
				required +
				PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES +
				PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES);
		}
		if (required == SIZE_MAX ||
		    required > config->banks[bank].length) {
			return false;
		}
		end[bank] =
			config->banks[bank].offset +
			config->banks[bank].length;
	}
	if (config->banks[0].offset < end[1] &&
	    config->banks[1].offset < end[0]) {
		return false;
	}
	return true;
}

int pqcp_fleet_policy_store_init(
	struct pqcp_fleet_policy_store *store,
	const struct pqcp_fleet_policy_store_config *config)
{
	int ret;

	if (store == NULL || !config_valid(config)) {
		return -EINVAL;
	}
	memset(store, 0, sizeof(*store));
	store->config = *config;
	store->next_sequence = 1U;
	store->initialized = true;
	ret = storage_lock(store);
	if (ret != 0) {
		store->initialized = false;
		return ret;
	}
	ret = recover_locked(store, NULL);
	secure_zero(
		store->config.scratch,
		store->config.scratch_capacity);
	ret = storage_unlock(
		store, ret == -ENOENT ? 0 : ret);
	return ret;
}

int pqcp_fleet_policy_store_recover(
	struct pqcp_fleet_policy_store *store,
	struct pqcp_fleet_policy_repair_report *report)
{
	int ret;

	if (store == NULL || !store->initialized) {
		return -EINVAL;
	}
	ret = storage_lock(store);
	if (ret != 0) {
		return ret;
	}
	ret = recover_locked(store, report);
	secure_zero(
		store->config.scratch,
		store->config.scratch_capacity);
	return storage_unlock(store, ret);
}

static int advance_floor_locked(
	struct pqcp_fleet_policy_store *store,
	uint64_t generation, uint64_t epoch)
{
	int ret = 0;

	if (generation > store->rollback_generation_floor) {
		store->rollback_generation_floor = generation;
	}
	if (epoch > store->rollback_epoch_floor) {
		store->rollback_epoch_floor = epoch;
	}
	if (store->config.backend.advance_rollback_floor != NULL) {
		ret = store->config.backend.advance_rollback_floor(
			store->config.backend.context,
			store->rollback_generation_floor,
			store->rollback_epoch_floor);
	}
	store->floor_sync_pending = ret != 0;
	return ret;
}

int pqcp_fleet_policy_store_commit(
	struct pqcp_fleet_policy_store *store,
	const struct pqcp_fleet_policy_commit *commit,
	struct pqcp_fleet_policy_commit_result *result)
{
	struct pqcp_fleet_policy_record_info record;
	uint64_t current_generation;
	uint64_t minimum_epoch;
	uint64_t generation;
	size_t target;
	bool compacted = false;
	int ret;

	if (store == NULL || !store->initialized ||
	    commit == NULL || commit->policy == NULL ||
	    commit->policy_length == 0U ||
	    commit->policy_length >
		    store->config.maximum_payload_bytes ||
	    commit->policy_epoch == 0U ||
	    (commit->flags & ~KNOWN_RECORD_FLAGS) != 0U) {
		return -EINVAL;
	}
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	ret = storage_lock(store);
	if (ret != 0) {
		return ret;
	}
	current_generation =
		store->policy_available ?
			store->active_policy.generation :
			store->rollback_generation_floor;
	minimum_epoch =
		store->policy_available ?
			store->active_policy.epoch :
			store->rollback_epoch_floor;
	if (store->rollback_epoch_floor > minimum_epoch) {
		minimum_epoch = store->rollback_epoch_floor;
	}
	if (commit->expected_generation !=
	    current_generation) {
		ret = -ESTALE;
		goto out;
	}
	if (commit->policy_epoch < minimum_epoch) {
		ret = -EKEYREJECTED;
		goto out;
	}
	if (current_generation == UINT64_MAX ||
	    store->next_sequence == UINT64_MAX) {
		ret = -EOVERFLOW;
		goto out;
	}
	generation = current_generation + 1U;
	memset(&record, 0, sizeof(record));
	if (!store->policy_available) {
		const uint64_t erase0 =
			store->bank[0].erase_cycles[0];
		const uint64_t erase1 =
			store->bank[1].erase_cycles[1];

		target = erase1 < erase0 ? 1U : 0U;
		ret = create_bank_with_policy_locked(
			store, target, commit->policy,
			commit->policy_length, generation,
			commit->policy_epoch, commit->flags,
			&record);
	} else {
		ret = ensure_append_space_locked(
			store, commit->policy_length,
			&compacted);
		if (ret == 0) {
			struct pqcp_fleet_policy_bank_info *active =
				&store->bank[
					store->active_bank];

			ret = write_record_to_bank(
				store, store->active_bank,
				active, active->append_offset,
				PQCP_FLEET_POLICY_RECORD_POLICY,
				commit->flags, generation,
				commit->policy_epoch,
				store->next_sequence,
				commit->policy,
				commit->policy_length,
				store->active_tail_digest,
				&record);
			if (ret == 0) {
				store->active_policy = record;
				memcpy(
					store->active_tail_digest,
					record.digest,
					sizeof(store->
						active_tail_digest));
				store->next_sequence++;
			}
		}
	}
	if (ret != 0) {
		goto out;
	}
	if (result != NULL) {
		result->record = record;
		result->bank = store->active_bank;
		result->compacted = compacted;
		result->committed = true;
	}
	ret = advance_floor_locked(
		store, generation, commit->policy_epoch);
	if (result != NULL) {
		result->rollback_floor_synchronized =
			ret == 0;
	}
out:
	secure_zero(
		store->config.scratch,
		store->config.scratch_capacity);
	return storage_unlock(store, ret);
}

int pqcp_fleet_policy_store_load(
	struct pqcp_fleet_policy_store *store,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length,
	struct pqcp_fleet_policy_record_info *record)
{
	int ret;

	if (store == NULL || !store->initialized) {
		return -EINVAL;
	}
	ret = storage_lock(store);
	if (ret != 0) {
		return ret;
	}
	ret = load_locked(
		store, output, output_capacity,
		output_length, record);
	secure_zero(
		store->config.scratch,
		store->config.scratch_capacity);
	return storage_unlock(store, ret);
}

int pqcp_fleet_policy_journal_append(
	struct pqcp_fleet_policy_store *store,
	const struct pqcp_fleet_policy_journal_append *append,
	struct pqcp_fleet_policy_record_info *record)
{
	struct pqcp_fleet_policy_record_info committed;
	struct pqcp_fleet_policy_bank_info *active;
	int ret;

	if (store == NULL || !store->initialized ||
	    append == NULL ||
	    append->kind == PQCP_FLEET_POLICY_RECORD_POLICY ||
	    !kind_valid(append->kind) ||
	    append->payload_length >
		    store->config.maximum_payload_bytes ||
	    (append->payload_length != 0U &&
	     append->payload == NULL) ||
	    (append->flags & ~KNOWN_RECORD_FLAGS) != 0U) {
		return -EINVAL;
	}
	ret = storage_lock(store);
	if (ret != 0) {
		return ret;
	}
	if (!store->policy_available) {
		ret = -ENOENT;
		goto out;
	}
	if (store->next_sequence == UINT64_MAX) {
		ret = -EOVERFLOW;
		goto out;
	}
	ret = ensure_append_space_locked(
		store, append->payload_length, NULL);
	if (ret != 0) {
		goto out;
	}
	active = &store->bank[store->active_bank];
	ret = write_record_to_bank(
		store, store->active_bank, active,
		active->append_offset, append->kind,
		append->flags,
		store->active_policy.generation,
		store->active_policy.epoch,
		store->next_sequence, append->payload,
		append->payload_length,
		store->active_tail_digest, &committed);
	if (ret == 0) {
		memcpy(store->active_tail_digest,
		       committed.digest,
		       sizeof(store->active_tail_digest));
		store->next_sequence++;
		if (record != NULL) {
			*record = committed;
		}
	}
out:
	secure_zero(
		store->config.scratch,
		store->config.scratch_capacity);
	return storage_unlock(store, ret);
}

int pqcp_fleet_policy_store_compact(
	struct pqcp_fleet_policy_store *store)
{
	int ret;

	if (store == NULL || !store->initialized) {
		return -EINVAL;
	}
	ret = storage_lock(store);
	if (ret != 0) {
		return ret;
	}
	ret = compact_locked(store);
	secure_zero(
		store->config.scratch,
		store->config.scratch_capacity);
	return storage_unlock(store, ret);
}

static bool candidate_better(
	const struct pqcp_fleet_policy_bank_info *candidate,
	const struct pqcp_fleet_policy_bank_info *current)
{
	if (candidate->policy.generation !=
	    current->policy.generation) {
		return candidate->policy.generation >
		       current->policy.generation;
	}
	if (candidate->policy.epoch !=
	    current->policy.epoch) {
		return candidate->policy.epoch >
		       current->policy.epoch;
	}
	if (candidate->bank_generation !=
	    current->bank_generation) {
		return candidate->bank_generation >
		       current->bank_generation;
	}
	return candidate->policy.sequence >
	       current->policy.sequence;
}

static int recover_locked(
	struct pqcp_fleet_policy_store *store,
	struct pqcp_fleet_policy_repair_report *report)
{
	size_t selected = PQCP_FLEET_POLICY_STORE_BANK_COUNT;
	bool ambiguous = false;
	int first_error = 0;
	int ret;

	if (report != NULL) {
		memset(report, 0, sizeof(*report));
	}
	store->policy_available = false;
	store->quarantine_mask = 0U;
	store->floor_sync_pending = false;
	memset(&store->active_policy, 0,
	       sizeof(store->active_policy));
	memset(store->active_tail_digest, 0,
	       sizeof(store->active_tail_digest));
	ret = read_rollback_floor_locked(store);
	if (ret != 0) {
		return ret;
	}
	for (size_t bank = 0U;
	     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
	     ++bank) {
		ret = scan_bank(store, bank, &store->bank[bank]);
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
		if (report != NULL) {
			report->before[bank] =
				store->bank[bank].status;
		}
		if (store->bank[bank].status ==
			    PQCP_FLEET_POLICY_BANK_CORRUPT ||
		    store->bank[bank].status ==
			    PQCP_FLEET_POLICY_BANK_SCAN_LIMIT) {
			store->bank[bank].quarantined = true;
			store->quarantine_mask |=
				(uint32_t)1U << bank;
		}
		if (!bank_policy_usable(&store->bank[bank])) {
			continue;
		}
		if (store->bank[bank].policy.generation <
			    store->rollback_generation_floor ||
		    store->bank[bank].policy.epoch <
			    store->rollback_epoch_floor) {
			store->bank[bank].status =
				PQCP_FLEET_POLICY_BANK_ROLLBACK;
			store->bank[bank].quarantined = true;
			store->quarantine_mask |=
				(uint32_t)1U << bank;
			continue;
		}
		if (selected ==
		    PQCP_FLEET_POLICY_STORE_BANK_COUNT) {
			selected = bank;
			continue;
		}
		if (store->bank[bank].policy.generation ==
			    store->bank[selected].policy.generation &&
		    store->bank[bank].policy.epoch ==
			    store->bank[selected].policy.epoch &&
		    (store->bank[bank].policy.payload_length !=
			     store->bank[selected].
				     policy.payload_length ||
		     store->bank[bank].policy.payload_checksum !=
			     store->bank[selected].
				     policy.payload_checksum)) {
			ambiguous = true;
			continue;
		}
		if (candidate_better(
			    &store->bank[bank],
			    &store->bank[selected])) {
			selected = bank;
		}
	}
	store->recovery_count =
		add_saturated(store->recovery_count, 1U);
	if (first_error != 0) {
		store->last_recovery_error = first_error;
		if (report != NULL) {
			report->recovery_result = first_error;
			report_fill(store, report);
		}
		return first_error;
	}
	if (ambiguous) {
		for (size_t bank = 0U;
		     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
		     ++bank) {
			if (bank_policy_usable(
				    &store->bank[bank])) {
				store->bank[bank].quarantined =
					true;
				store->quarantine_mask |=
					(uint32_t)1U << bank;
			}
		}
		store->last_recovery_error = -EBADMSG;
		if (report != NULL) {
			report->recovery_result = -EBADMSG;
			report_fill(store, report);
		}
		return -EBADMSG;
	}
	if (selected ==
	    PQCP_FLEET_POLICY_STORE_BANK_COUNT) {
		int unavailable_result = -ENOENT;

		for (size_t bank = 0U;
		     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
		     ++bank) {
			if (store->bank[bank].status ==
			    PQCP_FLEET_POLICY_BANK_SCAN_LIMIT) {
				unavailable_result = -E2BIG;
				break;
			}
			if (store->bank[bank].status ==
			    PQCP_FLEET_POLICY_BANK_ROLLBACK) {
				unavailable_result =
					-EKEYREJECTED;
			} else if (
				store->bank[bank].status ==
					PQCP_FLEET_POLICY_BANK_CORRUPT &&
				unavailable_result == -ENOENT) {
				unavailable_result = -EBADMSG;
			}
		}
		store->active_bank = 0U;
		store->next_sequence = 1U;
		store->last_recovery_error =
			unavailable_result;
		if (report != NULL) {
			report->recovery_result =
				unavailable_result;
			report_fill(store, report);
		}
		return unavailable_result;
	}
	store->active_bank = selected;
	store->active_policy =
		store->bank[selected].policy;
	memcpy(store->active_tail_digest,
	       store->bank[selected].tail_digest,
	       sizeof(store->active_tail_digest));
	if (store->bank[selected].last_sequence ==
	    UINT64_MAX) {
		store->last_recovery_error = -EOVERFLOW;
		return -EOVERFLOW;
	}
	store->next_sequence =
		store->bank[selected].last_sequence + 1U;
	store->policy_available = true;
	store->last_recovery_error = 0;
	if (store->active_policy.generation >
	    store->rollback_generation_floor) {
		store->rollback_generation_floor =
			store->active_policy.generation;
	}
	if (store->active_policy.epoch >
	    store->rollback_epoch_floor) {
		store->rollback_epoch_floor =
			store->active_policy.epoch;
	}
	if (store->config.backend.advance_rollback_floor != NULL) {
		ret = store->config.backend.advance_rollback_floor(
			store->config.backend.context,
			store->rollback_generation_floor,
			store->rollback_epoch_floor);
		if (ret != 0) {
			store->floor_sync_pending = true;
			store->last_recovery_error = ret;
		}
	}
	if (report != NULL) {
		report->actions |=
			PQCP_FLEET_POLICY_REPAIR_RECOVERED;
		if (store->quarantine_mask != 0U) {
			report->actions |=
				PQCP_FLEET_POLICY_REPAIR_QUARANTINED;
		}
		report->recovery_result =
			store->last_recovery_error;
		report_fill(store, report);
	}
	return store->last_recovery_error;
}

static void wear_baseline(
	const struct pqcp_fleet_policy_store *store,
	uint64_t erase_cycles[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT],
	uint64_t program_bytes[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT])
{
	for (size_t bank = 0U;
	     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
	     ++bank) {
		erase_cycles[bank] =
			store->bank[0].erase_cycles[bank] >
					store->bank[1].
						erase_cycles[bank] ?
				store->bank[0].erase_cycles[bank] :
				store->bank[1].erase_cycles[bank];
		program_bytes[bank] =
			store->bank[0].program_bytes[bank] >
					store->bank[1].
						program_bytes[bank] ?
				store->bank[0].program_bytes[bank] :
				store->bank[1].program_bytes[bank];
	}
}

static int erase_bank_locked(
	struct pqcp_fleet_policy_store *store,
	size_t bank, bool secure_required,
	bool *secure_used)
{
	const struct pqcp_fleet_policy_bank_region *region;
	struct pqcp_fleet_policy_bank_info wear_info;
	uint64_t erase_cycles[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	uint64_t program_bytes[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	int ret;

	if (bank >= PQCP_FLEET_POLICY_STORE_BANK_COUNT) {
		return -EINVAL;
	}
	wear_baseline(store, erase_cycles, program_bytes);
	wear_info = store->bank[bank];
	memcpy(wear_info.erase_cycles, erase_cycles,
	       sizeof(erase_cycles));
	memcpy(wear_info.program_bytes, program_bytes,
	       sizeof(program_bytes));
	if (!wear_allows(
		    store, &wear_info, bank, 1U, 0U)) {
		return -EDQUOT;
	}
	region = &store->config.banks[bank];
	if (store->config.backend.secure_erase != NULL) {
		ret = store->config.backend.secure_erase(
			store->config.backend.context,
			region->offset, region->length);
		if (ret == 0 && secure_used != NULL) {
			*secure_used = true;
		}
	} else if (secure_required) {
		return -ENOTSUP;
	} else {
		ret = store->config.backend.erase(
			store->config.backend.context,
			region->offset, region->length);
	}
	if (ret == 0) {
		ret = storage_sync(store);
	}
	if (ret == 0) {
		erase_cycles[bank] =
			add_saturated(erase_cycles[bank], 1U);
		memset(&store->bank[bank], 0,
		       sizeof(store->bank[bank]));
		store->bank[bank].status =
			PQCP_FLEET_POLICY_BANK_EMPTY;
		store->bank[bank].tail_clean = true;
		store->bank[bank].append_offset =
			PQCP_FLEET_POLICY_STORE_BANK_PREFIX_BYTES;
		memcpy(store->bank[bank].erase_cycles,
		       erase_cycles, sizeof(erase_cycles));
		memcpy(store->bank[bank].program_bytes,
		       program_bytes, sizeof(program_bytes));
		store->quarantine_mask &=
			~((uint32_t)1U << bank);
	}
	return ret;
}

static int write_record_to_bank(
	struct pqcp_fleet_policy_store *store,
	size_t bank,
	struct pqcp_fleet_policy_bank_info *info,
	size_t offset,
	enum pqcp_fleet_policy_record_kind kind,
	uint32_t flags,
	uint64_t generation,
	uint64_t epoch,
	uint64_t sequence,
	const uint8_t *payload,
	size_t payload_length,
	const uint8_t previous_digest[
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES],
	struct pqcp_fleet_policy_record_info *record)
{
	uint8_t header_bytes[
		PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES];
	uint8_t prefix[
		PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES];
	uint8_t marker[
		PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES];
	struct record_header header;
	const uint8_t *stable_payload =
		store->config.scratch +
		PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES;
	size_t committed_bytes;
	size_t next_offset;
	int ret;

	if (bank >= PQCP_FLEET_POLICY_STORE_BANK_COUNT ||
	    info == NULL || !kind_valid(kind) ||
	    (flags & ~KNOWN_RECORD_FLAGS) != 0U ||
	    generation == 0U || sequence == 0U ||
	    payload_length >
		    store->config.maximum_payload_bytes ||
	    payload_length > UINT32_MAX ||
	    (payload_length != 0U && payload == NULL) ||
	    (kind == PQCP_FLEET_POLICY_RECORD_POLICY &&
	     payload_length == 0U) ||
	    previous_digest == NULL) {
		return -EINVAL;
	}
	if (payload_length >
	    SIZE_MAX -
		    PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES -
		    PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES) {
		return -EOVERFLOW;
	}
	committed_bytes =
		PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES +
		payload_length +
		PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES;
	if (offset >
		    store->config.banks[bank].length ||
	    committed_bytes >
		    store->config.banks[bank].length - offset) {
		return -ENOSPC;
	}
	next_offset = align_record(offset + committed_bytes);
	if (next_offset == SIZE_MAX ||
	    next_offset > store->config.banks[bank].length) {
		return -ENOSPC;
	}
	if (!wear_allows(
		    store, info, bank, 0U, committed_bytes)) {
		return -EDQUOT;
	}
	if (payload_length != 0U) {
		memmove(
			store->config.scratch +
				PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES,
			payload, payload_length);
	}
	memset(&header, 0, sizeof(header));
	header.kind = kind;
	header.flags = flags;
	header.generation = generation;
	header.epoch = epoch;
	header.sequence = sequence;
	header.payload_length = (uint32_t)payload_length;
	memcpy(header.previous_digest, previous_digest,
	       sizeof(header.previous_digest));
	ret = checksum_bytes(
		store,
		payload_length != 0U ?
			stable_payload : store->config.scratch,
		payload_length, &header.payload_checksum);
	if (ret != 0) {
		return ret;
	}
	encode_record_prefix(&header, prefix);
	ret = hash_record(
		store, prefix,
		payload_length != 0U ?
			stable_payload : store->config.scratch,
		payload_length, header.digest);
	if (ret != 0) {
		return ret;
	}
	encode_record_header(&header, header_bytes);
	ret = checksum_bytes(
		store, header_bytes, 112U,
		&header.checksum);
	if (ret != 0) {
		return ret;
	}
	encode_record_header(&header, header_bytes);
	ret = storage_write(
		store, bank, offset, header_bytes,
		sizeof(header_bytes));
	if (ret == 0 && payload_length != 0U) {
		ret = storage_write(
			store, bank,
			offset +
				PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES,
			stable_payload, payload_length);
	}
	if (ret == 0) {
		ret = storage_sync(store);
	}
	if (ret != 0) {
		info->tail_clean = false;
		info->status =
			PQCP_FLEET_POLICY_BANK_RECOVERABLE;
		info->corruption_offset = offset;
		return ret;
	}
	encode_commit_marker(
		RECORD_COMMIT_MAGIC, header.checksum,
		header.sequence, marker);
	ret = storage_write(
		store, bank,
		offset +
			PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES +
			payload_length,
		marker, sizeof(marker));
	if (ret == 0) {
		ret = storage_sync(store);
	}
	if (ret != 0) {
		info->tail_clean = false;
		info->status =
			PQCP_FLEET_POLICY_BANK_RECOVERABLE;
		info->corruption_offset = offset;
		return ret;
	}
	info->program_bytes[bank] = add_saturated(
		info->program_bytes[bank], committed_bytes);
	info->records_scanned++;
	info->bytes_scanned = add_size_saturated(
		info->bytes_scanned, committed_bytes);
	info->last_sequence = sequence;
	info->append_offset = next_offset;
	info->tail_clean = true;
	memcpy(info->tail_digest, header.digest,
	       sizeof(info->tail_digest));
	if (kind == PQCP_FLEET_POLICY_RECORD_POLICY) {
		record_to_info(&header, offset, &info->policy);
		info->policy_present = true;
	}
	if (info->activated) {
		info->status = wear_exceeded(store, info, bank) ?
			PQCP_FLEET_POLICY_BANK_WORN :
			PQCP_FLEET_POLICY_BANK_VALID;
	}
	if (record != NULL) {
		record_to_info(&header, offset, record);
	}
	return 0;
}

static uint64_t next_bank_generation(
	const struct pqcp_fleet_policy_store *store)
{
	uint64_t generation =
		store->bank[0].bank_generation >
				store->bank[1].bank_generation ?
			store->bank[0].bank_generation :
			store->bank[1].bank_generation;

	return generation == UINT64_MAX ?
		0U : generation + 1U;
}

static int create_bank_with_policy_locked(
	struct pqcp_fleet_policy_store *store,
	size_t target,
	const uint8_t *policy,
	size_t policy_length,
	uint64_t generation,
	uint64_t epoch,
	uint32_t flags,
	struct pqcp_fleet_policy_record_info *record)
{
	uint8_t header_bytes[
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES];
	uint8_t marker[
		PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES];
	struct pqcp_fleet_policy_bank_info prepared;
	struct pqcp_fleet_policy_bank_info wear_info;
	struct bank_header header;
	uint64_t baseline_erase[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	uint64_t baseline_program[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	uint64_t bank_generation;
	uint64_t total_program;
	bool secure_used = false;
	int ret;

	if (target >= PQCP_FLEET_POLICY_STORE_BANK_COUNT ||
	    policy == NULL || policy_length == 0U ||
	    generation == 0U || store->next_sequence == 0U ||
	    store->next_sequence == UINT64_MAX) {
		return -EINVAL;
	}
	if (policy_length >
	    UINT64_MAX -
		    PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES -
		    PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES * 2U -
		    PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES) {
		return -EOVERFLOW;
	}
	total_program =
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES +
		PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES * 2U +
		PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES +
		policy_length;
	wear_baseline(
		store, baseline_erase, baseline_program);
	wear_info = store->bank[target];
	memcpy(wear_info.erase_cycles, baseline_erase,
	       sizeof(baseline_erase));
	memcpy(wear_info.program_bytes, baseline_program,
	       sizeof(baseline_program));
	if (!wear_allows(
		    store, &wear_info, target,
		    1U, total_program)) {
		return -EDQUOT;
	}
	bank_generation = next_bank_generation(store);
	if (bank_generation == 0U) {
		return -EOVERFLOW;
	}
	ret = erase_bank_locked(
		store, target, false, &secure_used);
	if (ret != 0) {
		return ret;
	}
	prepared = store->bank[target];
	memset(&header, 0, sizeof(header));
	header.bank_index = (uint32_t)target;
	header.bank_generation = bank_generation;
	header.previous_generation =
		store->policy_available ?
			store->active_policy.generation :
			store->rollback_generation_floor;
	header.previous_epoch =
		store->policy_available ?
			store->active_policy.epoch :
			store->rollback_epoch_floor;
	header.first_sequence = store->next_sequence;
	memcpy(header.erase_cycles, prepared.erase_cycles,
	       sizeof(header.erase_cycles));
	memcpy(header.program_bytes, prepared.program_bytes,
	       sizeof(header.program_bytes));
	if (store->policy_available) {
		memcpy(header.previous_tail_digest,
		       store->active_tail_digest,
		       sizeof(header.previous_tail_digest));
	}
	encode_bank_header(&header, header_bytes);
	ret = checksum_bytes(
		store, header_bytes, 112U, &header.checksum);
	if (ret != 0) {
		return ret;
	}
	encode_bank_header(&header, header_bytes);
	ret = storage_write(
		store, target, 0U, header_bytes,
		sizeof(header_bytes));
	if (ret == 0) {
		ret = storage_sync(store);
	}
	if (ret != 0) {
		return ret;
	}
	prepared.status =
		PQCP_FLEET_POLICY_BANK_UNCOMMITTED;
	prepared.header_valid = true;
	prepared.bank_generation = bank_generation;
	prepared.previous_generation =
		header.previous_generation;
	prepared.previous_epoch = header.previous_epoch;
	prepared.first_sequence = header.first_sequence;
	prepared.append_offset =
		PQCP_FLEET_POLICY_STORE_BANK_PREFIX_BYTES;
	prepared.tail_clean = true;
	prepared.bytes_scanned =
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES;
	prepared.program_bytes[target] = add_saturated(
		prepared.program_bytes[target],
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES);
	memcpy(prepared.previous_tail_digest,
	       header.previous_tail_digest,
	       sizeof(prepared.previous_tail_digest));
	ret = write_record_to_bank(
		store, target, &prepared,
		PQCP_FLEET_POLICY_STORE_BANK_PREFIX_BYTES,
		PQCP_FLEET_POLICY_RECORD_POLICY,
		flags, generation, epoch,
		store->next_sequence, policy, policy_length,
		header.previous_tail_digest, record);
	if (ret != 0) {
		store->bank[target] = prepared;
		return ret;
	}
	encode_commit_marker(
		BANK_COMMIT_MAGIC, header.checksum,
		header.bank_generation, marker);
	ret = storage_write(
		store, target,
		PQCP_FLEET_POLICY_STORE_BANK_HEADER_BYTES,
		marker, sizeof(marker));
	if (ret == 0) {
		ret = storage_sync(store);
	}
	if (ret != 0) {
		store->bank[target] = prepared;
		return ret;
	}
	prepared.program_bytes[target] = add_saturated(
		prepared.program_bytes[target], sizeof(marker));
	prepared.bytes_scanned = add_size_saturated(
		prepared.bytes_scanned, sizeof(marker));
	prepared.activated = true;
	prepared.status = wear_exceeded(
		store, &prepared, target) ?
			PQCP_FLEET_POLICY_BANK_WORN :
			PQCP_FLEET_POLICY_BANK_VALID;
	store->bank[target] = prepared;
	store->active_bank = target;
	store->active_policy = prepared.policy;
	memcpy(store->active_tail_digest,
	       prepared.tail_digest,
	       sizeof(store->active_tail_digest));
	store->policy_available = true;
	store->quarantine_mask &=
		~((uint32_t)1U << target);
	store->next_sequence++;
	return 0;
}

static int load_locked(
	struct pqcp_fleet_policy_store *store,
	uint8_t *output, size_t output_capacity,
	size_t *output_length,
	struct pqcp_fleet_policy_record_info *record)
{
	uint8_t header_bytes[
		PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES];
	uint8_t marker[
		PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES];
	uint8_t prefix[
		PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES];
	uint8_t digest[PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	struct record_header header;
	uint32_t checksum;
	int ret;

	if (!store->policy_available) {
		return -ENOENT;
	}
	if (output == NULL || output_length == NULL) {
		return -EINVAL;
	}
	if (output_capacity <
	    store->active_policy.payload_length) {
		return -ENOSPC;
	}
	ret = storage_read(
		store, store->active_bank,
		store->active_policy.storage_offset,
		header_bytes, sizeof(header_bytes));
	if (ret == 0) {
		ret = decode_record_header(
			store, header_bytes, &header);
	}
	if (ret != 0) {
		return ret;
	}
	if (header.kind !=
		    PQCP_FLEET_POLICY_RECORD_POLICY ||
	    header.generation !=
		    store->active_policy.generation ||
	    header.epoch != store->active_policy.epoch ||
	    header.sequence !=
		    store->active_policy.sequence ||
	    header.payload_length !=
		    store->active_policy.payload_length) {
		return -EBADMSG;
	}
	ret = storage_read(
		store, store->active_bank,
		store->active_policy.storage_offset +
			PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES,
		output, header.payload_length);
	if (ret != 0) {
		return ret;
	}
	ret = checksum_bytes(
		store, output, header.payload_length,
		&checksum);
	if (ret != 0 ||
	    checksum != header.payload_checksum) {
		secure_zero(output, header.payload_length);
		return ret != 0 ? ret : -EBADMSG;
	}
	encode_record_prefix(&header, prefix);
	ret = hash_record(
		store, prefix, output,
		header.payload_length, digest);
	if (ret != 0 ||
	    memcmp(digest, header.digest,
		   sizeof(digest)) != 0) {
		secure_zero(output, header.payload_length);
		secure_zero(digest, sizeof(digest));
		return ret != 0 ? ret : -EBADMSG;
	}
	ret = storage_read(
		store, store->active_bank,
		store->active_policy.storage_offset +
			PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES +
			header.payload_length,
		marker, sizeof(marker));
	if (ret != 0 ||
	    !commit_marker_valid(
		    marker, RECORD_COMMIT_MAGIC,
		    header.checksum, header.sequence)) {
		secure_zero(output, header.payload_length);
		secure_zero(digest, sizeof(digest));
		return ret != 0 ? ret : -EBADMSG;
	}
	*output_length = header.payload_length;
	if (record != NULL) {
		*record = store->active_policy;
	}
	secure_zero(digest, sizeof(digest));
	return 0;
}

static int compact_locked(
	struct pqcp_fleet_policy_store *store)
{
	size_t target;
	size_t policy_length = 0U;
	int ret;

	if (!store->policy_available) {
		return -ENOENT;
	}
	target = store->active_bank ^ 1U;
	ret = load_locked(
		store,
		store->config.scratch +
			PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES,
		store->config.maximum_payload_bytes,
		&policy_length, NULL);
	if (ret != 0) {
		return ret;
	}
	ret = create_bank_with_policy_locked(
		store, target,
		store->config.scratch +
			PQCP_FLEET_POLICY_STORE_HASH_PREFIX_BYTES,
		policy_length,
		store->active_policy.generation,
		store->active_policy.epoch,
		store->active_policy.flags |
			PQCP_FLEET_POLICY_RECORD_CHECKPOINT,
		NULL);
	secure_zero(
		store->config.scratch,
		store->config.scratch_capacity);
	if (ret == 0) {
		store->compaction_count =
			add_saturated(
				store->compaction_count, 1U);
	}
	return ret;
}

static int ensure_append_space_locked(
	struct pqcp_fleet_policy_store *store,
	size_t payload_length, bool *compacted)
{
	const struct pqcp_fleet_policy_bank_info *active;
	size_t committed_bytes;
	size_t next_offset;
	int ret;

	if (compacted != NULL) {
		*compacted = false;
	}
	if (!store->policy_available) {
		return -ENOENT;
	}
	if (payload_length >
	    SIZE_MAX -
		    PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES -
		    PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES) {
		return -EOVERFLOW;
	}
	committed_bytes =
		PQCP_FLEET_POLICY_STORE_RECORD_HEADER_BYTES +
		payload_length +
		PQCP_FLEET_POLICY_STORE_COMMIT_MARKER_BYTES;
	active = &store->bank[store->active_bank];
	next_offset = active->append_offset <=
			      SIZE_MAX - committed_bytes ?
		align_record(
			active->append_offset + committed_bytes) :
		SIZE_MAX;
	if (active->status ==
		    PQCP_FLEET_POLICY_BANK_VALID &&
	    active->tail_clean &&
	    next_offset != SIZE_MAX &&
	    next_offset <=
		    store->config.banks[
			    store->active_bank].length &&
	    wear_allows(
		    store, active, store->active_bank,
		    0U, committed_bytes)) {
		return 0;
	}
	if (!store->config.automatic_compaction) {
		if (!active->tail_clean) {
			return -EBADMSG;
		}
		if (!wear_allows(
			    store, active,
			    store->active_bank,
			    0U, committed_bytes)) {
			return -EDQUOT;
		}
		return -ENOSPC;
	}
	ret = compact_locked(store);
	if (ret != 0) {
		return ret;
	}
	if (compacted != NULL) {
		*compacted = true;
	}
	active = &store->bank[store->active_bank];
	next_offset = active->append_offset <=
			      SIZE_MAX - committed_bytes ?
		align_record(
			active->append_offset + committed_bytes) :
		SIZE_MAX;
	if (next_offset == SIZE_MAX ||
	    next_offset >
		    store->config.banks[
			    store->active_bank].length) {
		return -ENOSPC;
	}
	if (!wear_allows(
		    store, active, store->active_bank,
		    0U, committed_bytes)) {
		return -EDQUOT;
	}
	return 0;
}

static size_t snapshot_encode(
	const struct pqcp_fleet_policy_snapshot *snapshot,
	uint8_t output[256])
{
	size_t offset = 0U;

	write_u32(output + offset, snapshot->format_version);
	offset += 4U;
	write_u32(output + offset, snapshot->quarantine_mask);
	offset += 4U;
	write_u64(output + offset, snapshot->generation);
	offset += 8U;
	write_u64(output + offset, snapshot->epoch);
	offset += 8U;
	write_u64(output + offset, snapshot->next_sequence);
	offset += 8U;
	write_u64(
		output + offset,
		snapshot->rollback_generation_floor);
	offset += 8U;
	write_u64(
		output + offset,
		snapshot->rollback_epoch_floor);
	offset += 8U;
	write_u64(output + offset, snapshot->recovery_count);
	offset += 8U;
	write_u64(output + offset, snapshot->compaction_count);
	offset += 8U;
	write_u64(output + offset, snapshot->repair_count);
	offset += 8U;
	for (size_t bank = 0U;
	     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
	     ++bank) {
		write_u64(
			output + offset,
			snapshot->erase_cycles[bank]);
		offset += 8U;
	}
	for (size_t bank = 0U;
	     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
	     ++bank) {
		write_u64(
			output + offset,
			snapshot->program_bytes[bank]);
		offset += 8U;
	}
	write_u64(output + offset, snapshot->active_bank);
	offset += 8U;
	write_u64(output + offset, snapshot->policy_length);
	offset += 8U;
	write_u64(output + offset, snapshot->active_records);
	offset += 8U;
	write_u64(output + offset, snapshot->active_bytes);
	offset += 8U;
	write_u64(output + offset, snapshot->available_bytes);
	offset += 8U;
	for (size_t bank = 0U;
	     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
	     ++bank) {
		write_u32(
			output + offset,
			(uint32_t)snapshot->bank_status[bank]);
		offset += 4U;
	}
	write_u32(
		output + offset,
		snapshot->policy_available ? 1U : 0U);
	offset += 4U;
	write_u32(
		output + offset,
		snapshot->floor_sync_pending ? 1U : 0U);
	offset += 4U;
	memcpy(output + offset, snapshot->policy_digest,
	       sizeof(snapshot->policy_digest));
	offset += sizeof(snapshot->policy_digest);
	memcpy(output + offset,
	       snapshot->journal_tail_digest,
	       sizeof(snapshot->journal_tail_digest));
	offset += sizeof(snapshot->journal_tail_digest);
	return offset;
}

int pqcp_fleet_policy_store_snapshot(
	struct pqcp_fleet_policy_store *store,
	struct pqcp_fleet_policy_snapshot *snapshot)
{
	uint8_t encoded[256 +
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	size_t encoded_length;
	int ret;

	if (store == NULL || !store->initialized ||
	    snapshot == NULL) {
		return -EINVAL;
	}
	ret = storage_lock(store);
	if (ret != 0) {
		return ret;
	}
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->format_version =
		PQCP_FLEET_POLICY_STORE_FORMAT_VERSION;
	snapshot->quarantine_mask =
		store->quarantine_mask;
	snapshot->next_sequence = store->next_sequence;
	snapshot->rollback_generation_floor =
		store->rollback_generation_floor;
	snapshot->rollback_epoch_floor =
		store->rollback_epoch_floor;
	snapshot->recovery_count = store->recovery_count;
	snapshot->compaction_count = store->compaction_count;
	snapshot->repair_count = store->repair_count;
	snapshot->active_bank = store->active_bank;
	snapshot->policy_available =
		store->policy_available;
	snapshot->floor_sync_pending =
		store->floor_sync_pending;
	for (size_t bank = 0U;
	     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
	     ++bank) {
		snapshot->bank_status[bank] =
			store->bank[bank].status;
		snapshot->erase_cycles[bank] =
			store->bank[bank].erase_cycles[bank];
		snapshot->program_bytes[bank] =
			store->bank[bank].program_bytes[bank];
	}
	if (store->policy_available) {
		const struct pqcp_fleet_policy_bank_info *active =
			&store->bank[store->active_bank];

		snapshot->generation =
			store->active_policy.generation;
		snapshot->epoch = store->active_policy.epoch;
		snapshot->policy_length =
			store->active_policy.payload_length;
		snapshot->active_records =
			active->records_scanned;
		snapshot->active_bytes =
			active->append_offset;
		snapshot->available_bytes =
			active->append_offset <=
				store->config.banks[
					store->active_bank].length ?
				store->config.banks[
					store->active_bank].length -
					active->append_offset :
				0U;
		memcpy(snapshot->policy_digest,
		       store->active_policy.digest,
		       sizeof(snapshot->policy_digest));
		memcpy(snapshot->journal_tail_digest,
		       store->active_tail_digest,
		       sizeof(snapshot->
			       journal_tail_digest));
	}
	encoded_length = snapshot_encode(snapshot, encoded);
	ret = pqcp_fleet_sha256(
		encoded, encoded_length,
		snapshot->digest);
	if (ret == 0) {
		memcpy(encoded + encoded_length,
		       snapshot->digest,
		       sizeof(snapshot->digest));
		snapshot->checksum = crc32_default(
			encoded,
			encoded_length +
				sizeof(snapshot->digest));
	}
	secure_zero(encoded, sizeof(encoded));
	return storage_unlock(store, ret);
}

int pqcp_fleet_policy_snapshot_verify(
	const struct pqcp_fleet_policy_snapshot *snapshot)
{
	uint8_t encoded[256 +
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	uint8_t digest[
		PQCP_FLEET_POLICY_STORE_DIGEST_BYTES];
	size_t encoded_length;
	uint32_t checksum;
	int ret;

	if (snapshot == NULL ||
	    snapshot->format_version !=
		    PQCP_FLEET_POLICY_STORE_FORMAT_VERSION ||
	    snapshot->active_bank >=
		    PQCP_FLEET_POLICY_STORE_BANK_COUNT ||
	    snapshot->next_sequence == 0U ||
	    (snapshot->policy_available &&
	     (snapshot->generation == 0U ||
	      snapshot->epoch == 0U ||
	      snapshot->policy_length == 0U)) ||
	    (!snapshot->policy_available &&
	     (snapshot->generation != 0U ||
	      snapshot->epoch != 0U ||
	      snapshot->policy_length != 0U))) {
		return -EBADMSG;
	}
	encoded_length = snapshot_encode(snapshot, encoded);
	ret = pqcp_fleet_sha256(
		encoded, encoded_length, digest);
	if (ret != 0) {
		secure_zero(encoded, sizeof(encoded));
		return ret;
	}
	memcpy(encoded + encoded_length, digest,
	       sizeof(digest));
	checksum = crc32_default(
		encoded, encoded_length + sizeof(digest));
	ret = memcmp(
			digest, snapshot->digest,
			sizeof(digest)) == 0 &&
		      checksum == snapshot->checksum ?
		0 : -EBADMSG;
	secure_zero(encoded, sizeof(encoded));
	secure_zero(digest, sizeof(digest));
	return ret;
}

static bool bank_unrecoverable(
	const struct pqcp_fleet_policy_bank_info *info)
{
	return info->status ==
			PQCP_FLEET_POLICY_BANK_UNCOMMITTED ||
	       info->status ==
			PQCP_FLEET_POLICY_BANK_CORRUPT ||
	       info->status ==
			PQCP_FLEET_POLICY_BANK_ROLLBACK ||
	       info->status ==
			PQCP_FLEET_POLICY_BANK_SCAN_LIMIT ||
	       info->status ==
			PQCP_FLEET_POLICY_BANK_QUARANTINED;
}

int pqcp_fleet_policy_storage_repair(
	struct pqcp_fleet_policy_store *store,
	uint32_t flags,
	struct pqcp_fleet_policy_repair_report *report)
{
	enum pqcp_fleet_policy_bank_status before[
		PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	const uint32_t known_flags =
		PQCP_FLEET_POLICY_REPAIR_REBUILD_REDUNDANCY |
		PQCP_FLEET_POLICY_REPAIR_ERASE_UNRECOVERABLE |
		PQCP_FLEET_POLICY_REPAIR_REQUIRE_SECURE_ERASE;
	uint32_t actions = 0U;
	uint32_t erased_mask = 0U;
	uint32_t rebuilt_mask = 0U;
	bool secure_required;
	int recovery_result;
	int result = 0;
	int ret;

	if (store == NULL || !store->initialized ||
	    report == NULL ||
	    (flags & ~known_flags) != 0U ||
	    ((flags &
	      PQCP_FLEET_POLICY_REPAIR_REQUIRE_SECURE_ERASE) !=
		     0U &&
	     (flags &
	      PQCP_FLEET_POLICY_REPAIR_ERASE_UNRECOVERABLE) ==
		     0U)) {
		return -EINVAL;
	}
	ret = storage_lock(store);
	if (ret != 0) {
		return ret;
	}
	memset(report, 0, sizeof(*report));
	report->requested_flags = flags;
	recovery_result = recover_locked(store, NULL);
	for (size_t bank = 0U;
	     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
	     ++bank) {
		before[bank] = store->bank[bank].status;
		report->before[bank] = before[bank];
	}
	if (store->policy_available) {
		actions |= PQCP_FLEET_POLICY_REPAIR_RECOVERED;
	}
	if (store->quarantine_mask != 0U) {
		actions |=
			PQCP_FLEET_POLICY_REPAIR_QUARANTINED;
	}
	if (recovery_result != 0 &&
	    recovery_result != -ENOENT &&
	    !store->policy_available) {
		result = recovery_result;
	}
	secure_required =
		(flags &
		 PQCP_FLEET_POLICY_REPAIR_REQUIRE_SECURE_ERASE) !=
		0U;
	if ((flags &
	     PQCP_FLEET_POLICY_REPAIR_ERASE_UNRECOVERABLE) !=
	    0U) {
		for (size_t bank = 0U;
		     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
		     ++bank) {
			bool secure_used = false;

			if ((!bank_unrecoverable(
				     &store->bank[bank]) &&
			     store->bank[bank].status !=
				     PQCP_FLEET_POLICY_BANK_RECOVERABLE) ||
			    (store->policy_available &&
			     bank == store->active_bank)) {
				continue;
			}
			ret = erase_bank_locked(
				store, bank, secure_required,
				&secure_used);
			if (ret != 0) {
				if (result == 0) {
					result = ret;
				}
				continue;
			}
			erased_mask |= (uint32_t)1U << bank;
			actions |=
				PQCP_FLEET_POLICY_REPAIR_ERASED;
			if (secure_used) {
				actions |=
					PQCP_FLEET_POLICY_REPAIR_SECURE_ERASED;
			}
		}
	}
	if ((flags &
	     PQCP_FLEET_POLICY_REPAIR_REBUILD_REDUNDANCY) !=
		    0U &&
	    store->policy_available) {
		const size_t target = store->active_bank ^ 1U;

		ret = compact_locked(store);
		if (ret == 0) {
			rebuilt_mask |= (uint32_t)1U << target;
			actions |=
				PQCP_FLEET_POLICY_REPAIR_REBUILT |
				PQCP_FLEET_POLICY_REPAIR_REDUNDANCY_RESTORED;
		} else if (result == 0) {
			result = ret;
		}
	}
	if (!store->policy_available &&
	    erased_mask != 0U &&
	    (recovery_result == -ENOENT ||
	     recovery_result == -EBADMSG ||
	     recovery_result == -E2BIG ||
	     recovery_result == -EKEYREJECTED)) {
		result = 0;
	}
	if ((actions &
	     (PQCP_FLEET_POLICY_REPAIR_REBUILT |
	      PQCP_FLEET_POLICY_REPAIR_ERASED)) != 0U) {
		store->repair_count =
			add_saturated(store->repair_count, 1U);
	}
	report->actions = actions;
	report->erased_mask = erased_mask;
	report->rebuilt_mask = rebuilt_mask;
	report->recovery_result = recovery_result;
	report->repair_result = result;
	report_fill(store, report);
	secure_zero(
		store->config.scratch,
		store->config.scratch_capacity);
	return storage_unlock(store, result);
}

int pqcp_fleet_policy_store_secure_erase(
	struct pqcp_fleet_policy_store *store,
	uint32_t flags,
	struct pqcp_fleet_policy_repair_report *report)
{
	size_t order[PQCP_FLEET_POLICY_STORE_BANK_COUNT];
	uint32_t actions = 0U;
	uint32_t erased_mask = 0U;
	bool secure_required;
	int result = 0;
	int ret;

	if (store == NULL || !store->initialized ||
	    (flags & ~PQCP_FLEET_POLICY_ERASE_REQUIRE_SECURE) !=
		    0U) {
		return -EINVAL;
	}
	if (report != NULL) {
		memset(report, 0, sizeof(*report));
		report->requested_flags = flags;
	}
	ret = storage_lock(store);
	if (ret != 0) {
		return ret;
	}
	order[0] = store->policy_available ?
		store->active_bank ^ 1U : 0U;
	order[1] = order[0] ^ 1U;
	secure_required =
		(flags &
		 PQCP_FLEET_POLICY_ERASE_REQUIRE_SECURE) != 0U;
	if (report != NULL) {
		for (size_t bank = 0U;
		     bank < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
		     ++bank) {
			report->before[bank] =
				store->bank[bank].status;
		}
	}
	for (size_t index = 0U;
	     index < PQCP_FLEET_POLICY_STORE_BANK_COUNT;
	     ++index) {
		const size_t bank = order[index];
		bool secure_used = false;

		ret = erase_bank_locked(
			store, bank, secure_required,
			&secure_used);
		if (ret != 0) {
			result = ret;
			break;
		}
		erased_mask |= (uint32_t)1U << bank;
		actions |=
			PQCP_FLEET_POLICY_REPAIR_ERASED;
		if (secure_used) {
			actions |=
				PQCP_FLEET_POLICY_REPAIR_SECURE_ERASED;
		}
	}
	if (result == 0) {
		store->policy_available = false;
		store->active_bank = 0U;
		store->next_sequence = 1U;
		store->quarantine_mask = 0U;
		memset(&store->active_policy, 0,
		       sizeof(store->active_policy));
		memset(store->active_tail_digest, 0,
		       sizeof(store->active_tail_digest));
	} else {
		(void)recover_locked(store, NULL);
	}
	if (report != NULL) {
		report->actions = actions;
		report->erased_mask = erased_mask;
		report->repair_result = result;
		report_fill(store, report);
	}
	secure_zero(
		store->config.scratch,
		store->config.scratch_capacity);
	return storage_unlock(store, result);
}
