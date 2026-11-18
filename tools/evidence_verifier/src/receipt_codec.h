/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deterministic-CBOR codec for appraisal statements, log checkpoints,
 * receipts and consistency files. Byte-level layout: see
 * docs/transparent-appraisal-format.md. Every decoder is strict: canonical
 * integers, ascending integer keys, exact key set, definite lengths, exact
 * field sizes, no trailing bytes.
 *
 * The receipt and consistency structs are several KiB: heap-allocate them.
 */

#ifndef PQCP_EVIDENCE_VERIFIER_RECEIPT_CODEC_H_
#define PQCP_EVIDENCE_VERIFIER_RECEIPT_CODEC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/fleet_transparency.h>

#define RC_STATEMENT_TAG "pqcp-appraisal/1"
#define RC_VERDICT_OK "CHAIN OK"
#define RC_VERDICT_REJECT "REJECT"
#define RC_HEX_CHARS 64U
#define RC_SIGNATURE_BYTES 3309U
#define RC_MAX_STATEMENT_BYTES 512U
#define RC_MAX_PATH_NODES PQCP_FLEET_TRANSPARENCY_MAX_PROOF_NODES
#define RC_MAX_CHECKPOINT_BYTES 3600U
#define RC_MAX_RECEIPT_BYTES 8192U
#define RC_MAX_CONSISTENCY_BYTES 12288U

struct rc_statement {
	/** 64 lowercase hex chars or empty (passport did not replay). */
	char passport_digest_hex[RC_HEX_CHARS + 1U];
	bool has_device_pk_hash;
	uint8_t device_pk_hash[32];
	/** 64 lowercase hex chars or empty (no trail in transcript). */
	char trail_head_hex[RC_HEX_CHARS + 1U];
	char verdict[9];
	uint8_t verifier_sha256[32];
	bool signature_verified;
	uint8_t transcript_sha256[32];
};

struct rc_checkpoint {
	uint32_t schema_version;
	uint64_t tree_size;
	uint64_t timestamp_ms;
	uint64_t sequence;
	uint8_t log_id[32];
	uint8_t root[32];
	uint8_t signer_key_id[32];
	uint8_t transcript_digest[32];
	uint8_t signature[RC_SIGNATURE_BYTES];
};

struct rc_receipt {
	uint8_t statement[RC_MAX_STATEMENT_BYTES];
	size_t statement_length;
	uint64_t leaf_index;
	uint64_t tree_size;
	uint8_t path[RC_MAX_PATH_NODES][32];
	size_t path_count;
	struct rc_checkpoint checkpoint;
};

struct rc_consistency {
	uint64_t old_size;
	uint64_t new_size;
	uint8_t nodes[RC_MAX_PATH_NODES][32];
	size_t node_count;
	struct rc_checkpoint old_checkpoint;
	struct rc_checkpoint new_checkpoint;
};

/* All functions: 0 on success, -EBADMSG on any decode/shape failure,
 * -ENOSPC when the output buffer is too small, -EINVAL on bad arguments.
 */
int rc_statement_encode(const struct rc_statement *statement, uint8_t *out,
			size_t capacity, size_t *length);
int rc_statement_decode(const uint8_t *in, size_t length,
			struct rc_statement *statement);

int rc_checkpoint_encode(const struct rc_checkpoint *checkpoint, uint8_t *out,
			 size_t capacity, size_t *length);
int rc_checkpoint_decode(const uint8_t *in, size_t length,
			 struct rc_checkpoint *checkpoint);

int rc_receipt_encode(const struct rc_receipt *receipt, uint8_t *out,
		      size_t capacity, size_t *length);
int rc_receipt_decode(const uint8_t *in, size_t length,
		      struct rc_receipt *receipt);

int rc_consistency_encode(const struct rc_consistency *consistency,
			  uint8_t *out, size_t capacity, size_t *length);
int rc_consistency_decode(const uint8_t *in, size_t length,
			  struct rc_consistency *consistency);

/** Wrap an rc_checkpoint as the fleet struct (signature aliases rc storage). */
void rc_checkpoint_to_fleet(
	struct rc_checkpoint *checkpoint,
	struct pqcp_fleet_transparency_checkpoint *fleet);

/** Copy a signed fleet checkpoint into rc form. 0 or -EINVAL. */
int rc_checkpoint_from_fleet(
	const struct pqcp_fleet_transparency_checkpoint *fleet,
	struct rc_checkpoint *checkpoint);

#endif /* PQCP_EVIDENCE_VERIFIER_RECEIPT_CODEC_H_ */
