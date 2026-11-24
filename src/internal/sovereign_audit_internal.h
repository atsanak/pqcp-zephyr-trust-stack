/*
 * SPDX-License-Identifier: MIT
 */

#ifndef PQCP_SOVEREIGN_AUDIT_INTERNAL_H_
#define PQCP_SOVEREIGN_AUDIT_INTERNAL_H_

#include <limits.h>

#include <pqcp_zephyr/sovereign_audit.h>

#define PQCP_SOVEREIGN_AUDIT_EVENT_HASH_DOMAIN \
	"PQCP-SOVEREIGN-EVENT-V1"
#define PQCP_SOVEREIGN_AUDIT_EVENT_ID_DOMAIN \
	"PQCP-SOVEREIGN-EVENT-ID-V1"
#define PQCP_SOVEREIGN_AUDIT_TENANT_DOMAIN \
	"PQCP-SOVEREIGN-TENANT-V1"
#define PQCP_SOVEREIGN_AUDIT_LEDGER_SNAPSHOT_DOMAIN \
	"PQCP-SOVEREIGN-LEDGER-SNAPSHOT-V1"
#define PQCP_SOVEREIGN_AUDIT_BATCH_DOMAIN \
	"PQCP-SOVEREIGN-AUDIT-BATCH-V1"
#define PQCP_SOVEREIGN_AUDIT_RECEIPT_DOMAIN \
	"PQCP-SOVEREIGN-AUDIT-RECEIPTS-V1"
#define PQCP_SOVEREIGN_AUDIT_PSEUDONYM_DOMAIN \
	"PQCP-SOVEREIGN-PSEUDONYM-V1"

struct pqcp_sovereign_audit_writer {
	uint8_t *output;
	size_t capacity;
	size_t offset;
	int error;
};

struct pqcp_sovereign_audit_cbor_writer {
	uint8_t *output;
	size_t capacity;
	size_t offset;
	int error;
};

bool pqcp_sovereign_audit_internal_all_zero(
	const uint8_t *bytes,
	size_t length);
bool pqcp_sovereign_audit_internal_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length);
bool pqcp_sovereign_audit_internal_text_valid(
	const char *text,
	size_t capacity,
	bool allow_empty);
int pqcp_sovereign_audit_internal_copy_text(
	char *destination,
	size_t capacity,
	const char *source,
	bool allow_empty);
uint64_t pqcp_sovereign_audit_internal_add_u64(
	uint64_t left,
	uint64_t right);
uint32_t pqcp_sovereign_audit_internal_next_generation(
	uint32_t *generation);
uint64_t pqcp_sovereign_audit_internal_next_id(
	uint64_t *identifier);
void pqcp_sovereign_audit_internal_write_u16(
	uint8_t output[2],
	uint16_t value);
void pqcp_sovereign_audit_internal_write_u32(
	uint8_t output[4],
	uint32_t value);
void pqcp_sovereign_audit_internal_write_u64(
	uint8_t output[8],
	uint64_t value);
int pqcp_sovereign_audit_internal_sha256(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES]);
int pqcp_sovereign_audit_internal_sha256_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES]);
int pqcp_sovereign_audit_internal_scope_digest(
	const struct pqcp_sovereign_audit_tenant_scope *scope,
	uint8_t digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES]);
int pqcp_sovereign_audit_internal_projection_digest(
	const char *tenant_id,
	const char *value,
	size_t value_capacity,
	uint8_t digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES]);

void pqcp_sovereign_audit_writer_init(
	struct pqcp_sovereign_audit_writer *writer,
	uint8_t *output,
	size_t capacity);
int pqcp_sovereign_audit_writer_finish(
	struct pqcp_sovereign_audit_writer *writer,
	size_t *output_length);
void pqcp_sovereign_audit_writer_bytes(
	struct pqcp_sovereign_audit_writer *writer,
	const void *bytes,
	size_t length);
void pqcp_sovereign_audit_writer_char(
	struct pqcp_sovereign_audit_writer *writer,
	char value);
void pqcp_sovereign_audit_writer_text(
	struct pqcp_sovereign_audit_writer *writer,
	const char *text);
void pqcp_sovereign_audit_writer_u64(
	struct pqcp_sovereign_audit_writer *writer,
	uint64_t value);
void pqcp_sovereign_audit_writer_i64(
	struct pqcp_sovereign_audit_writer *writer,
	int64_t value);
void pqcp_sovereign_audit_writer_hex(
	struct pqcp_sovereign_audit_writer *writer,
	const uint8_t *bytes,
	size_t length);
void pqcp_sovereign_audit_writer_json_text(
	struct pqcp_sovereign_audit_writer *writer,
	const char *text);
void pqcp_sovereign_audit_writer_cef_header_text(
	struct pqcp_sovereign_audit_writer *writer,
	const char *text);
void pqcp_sovereign_audit_writer_cef_extension_text(
	struct pqcp_sovereign_audit_writer *writer,
	const char *text);

void pqcp_sovereign_audit_cbor_init(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	uint8_t *output,
	size_t capacity);
int pqcp_sovereign_audit_cbor_finish(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	size_t *output_length);
void pqcp_sovereign_audit_cbor_uint(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	uint64_t value);
void pqcp_sovereign_audit_cbor_int(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	int64_t value);
void pqcp_sovereign_audit_cbor_bool(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	bool value);
void pqcp_sovereign_audit_cbor_bytes(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	const uint8_t *bytes,
	size_t length);
void pqcp_sovereign_audit_cbor_text(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	const char *text);
void pqcp_sovereign_audit_cbor_array(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	size_t count);
void pqcp_sovereign_audit_cbor_map(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	size_t count);
void pqcp_sovereign_audit_cbor_event(
	struct pqcp_sovereign_audit_cbor_writer *writer,
	const struct pqcp_sovereign_event *event);
int pqcp_sovereign_audit_cbor_encode_batch_body(
	const struct pqcp_sovereign_export_batch *batch,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);

size_t pqcp_sovereign_audit_internal_physical_index(
	const struct pqcp_sovereign_event_ledger *ledger,
	size_t logical_index);
const struct pqcp_sovereign_event *
pqcp_sovereign_audit_internal_logical_event(
	const struct pqcp_sovereign_event_ledger *ledger,
	size_t logical_index);
int pqcp_sovereign_audit_internal_find_sequence(
	const struct pqcp_sovereign_event_ledger *ledger,
	uint64_t sequence,
	size_t *logical_index);
bool pqcp_sovereign_audit_internal_policy_matches(
	const struct pqcp_sovereign_audit_export_policy *policy,
	const struct pqcp_sovereign_event *event);
int pqcp_sovereign_audit_internal_encode_batch(
	const struct pqcp_sovereign_export_batch *batch,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);

#endif /* PQCP_SOVEREIGN_AUDIT_INTERNAL_H_ */
