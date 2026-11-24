/*
 * SPDX-License-Identifier: MIT
 */

#ifndef PQCP_EVIDENCE_CONTINUITY_INTERNAL_H_
#define PQCP_EVIDENCE_CONTINUITY_INTERNAL_H_

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/evidence_continuity.h>

#include "fleet_internal.h"

#define PQCP_EVIDENCE_CONTINUITY_RECORD_MAGIC 0x50454331U
#define PQCP_EVIDENCE_CONTINUITY_RECORD_HEADER_BYTES 72U
#define PQCP_EVIDENCE_CONTINUITY_RECORD_COMMITTED (1U << 0)
#define PQCP_EVIDENCE_CONTINUITY_RECORD_TOMBSTONE (1U << 1)

struct pqcp_evidence_continuity_record_header {
	uint32_t magic;
	uint32_t schema_version;
	enum pqcp_evidence_continuity_object object;
	uint32_t slot;
	uint64_t generation;
	uint64_t monotonic_counter;
	uint32_t payload_length;
	uint32_t flags;
	uint8_t payload_digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES];
};

bool pqcp_evidence_continuity_text_valid(
	const char *value,
	size_t capacity);
bool pqcp_evidence_continuity_digest_zero(
	const uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES]);
bool pqcp_evidence_continuity_digest_equal(
	const uint8_t left[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES],
	const uint8_t right[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES]);
bool pqcp_evidence_continuity_event_type_valid(
	enum pqcp_evidence_continuity_event_type type);
bool pqcp_evidence_continuity_severity_valid(
	enum pqcp_evidence_continuity_severity severity);
bool pqcp_evidence_continuity_anchor_state_valid(
	enum pqcp_evidence_continuity_anchor_state state);
uint32_t pqcp_evidence_continuity_next_generation(
	uint32_t *generation);
uint64_t pqcp_evidence_continuity_add_u64(
	uint64_t left,
	uint64_t right);
int pqcp_evidence_continuity_copy_text(
	char *destination,
	size_t capacity,
	const char *source);
void pqcp_evidence_continuity_write_u32(
	uint8_t output[4],
	uint32_t value);
void pqcp_evidence_continuity_write_u64(
	uint8_t output[8],
	uint64_t value);
uint32_t pqcp_evidence_continuity_read_u32(
	const uint8_t input[4]);
uint64_t pqcp_evidence_continuity_read_u64(
	const uint8_t input[8]);
void pqcp_evidence_continuity_secure_zero(
	void *memory,
	size_t length);
int pqcp_evidence_continuity_hash(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES]);
int pqcp_evidence_continuity_hash_parts(
	const char *domain,
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t count,
	uint8_t output[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES]);
int pqcp_evidence_continuity_anchor_digest(
	const struct pqcp_evidence_continuity_anchor *anchor,
	uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES]);
int pqcp_evidence_continuity_session_digest(
	const struct pqcp_evidence_continuity_boot_session *session,
	uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES]);
int pqcp_evidence_continuity_event_digest(
	const struct pqcp_evidence_continuity_event *event,
	uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES]);
int pqcp_evidence_continuity_checkpoint_digest(
	const struct pqcp_evidence_continuity_checkpoint *checkpoint,
	uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES]);
int pqcp_evidence_continuity_receipt_digest(
	const struct pqcp_evidence_continuity_witness_receipt *receipt,
	uint8_t digest[PQCP_EVIDENCE_CONTINUITY_DIGEST_BYTES]);
int pqcp_evidence_continuity_record_encode(
	const struct pqcp_evidence_continuity_record_header *header,
	const uint8_t *payload,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_evidence_continuity_record_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_evidence_continuity_record_header *header,
	const uint8_t **payload);
int pqcp_evidence_continuity_store_record(
	const struct pqcp_evidence_continuity_store *store,
	enum pqcp_evidence_continuity_object object,
	uint32_t slot,
	uint64_t generation,
	uint64_t monotonic_counter,
	const uint8_t *payload,
	size_t payload_length);
int pqcp_evidence_continuity_load_record(
	const struct pqcp_evidence_continuity_store *store,
	enum pqcp_evidence_continuity_object object,
	uint32_t slot,
	uint8_t *buffer,
	size_t buffer_capacity,
	struct pqcp_evidence_continuity_record_header *header,
	const uint8_t **payload);

#endif /* PQCP_EVIDENCE_CONTINUITY_INTERNAL_H_ */
