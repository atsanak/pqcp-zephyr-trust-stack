/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Passport signature capture and verification for the host verifier.
 *
 * Reassembles the chunked PQCP_DEPLOYMENT_PASSPORT_SIGNATURE /
 * PQCP_DEPLOYMENT_PASSPORT_PK_CHUNK / PQCP_DEPLOYMENT_PASSPORT_SIG_CHUNK
 * markers from a device transcript and verifies the ML-DSA-65 signature
 * with the same vendored mldsa-native code the firmware ships.
 */

#ifndef PQCP_EVIDENCE_VERIFIER_SIGNATURE_CHECK_H_
#define PQCP_EVIDENCE_VERIFIER_SIGNATURE_CHECK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SIGNATURE_PK_BYTES 1952U
#define SIGNATURE_SIG_BYTES 3309U
#define SIGNATURE_CHUNK_BYTES 128U
#define SIGNATURE_PK_CHUNKS \
	((SIGNATURE_PK_BYTES + SIGNATURE_CHUNK_BYTES - 1U) / \
	 SIGNATURE_CHUNK_BYTES)
#define SIGNATURE_SIG_CHUNKS \
	((SIGNATURE_SIG_BYTES + SIGNATURE_CHUNK_BYTES - 1U) / \
	 SIGNATURE_CHUNK_BYTES)
#define SIGNATURE_DIGEST_HEX_CHARS 64U

struct signature_capture {
	/** Header markers seen (must end at exactly 1). */
	unsigned long header_markers;
	/** True once any header or chunk marker was seen. */
	bool present;
	/** True when a marker failed to parse or repeated. */
	bool malformed;
	/** boot_post_gated flag from the header marker. */
	bool boot_post_gated;
	/** Passport digest the device claims to have signed. */
	char passport_digest_hex[SIGNATURE_DIGEST_HEX_CHARS + 1U];
	/** Bitmask of received public-key chunk indices. */
	uint32_t pk_chunks_seen;
	/** Bitmask of received signature chunk indices. */
	uint32_t sig_chunks_seen;
	/** Reassembled ML-DSA-65 public key. */
	uint8_t public_key[SIGNATURE_PK_BYTES];
	/** Reassembled ML-DSA-65 signature. */
	uint8_t signature[SIGNATURE_SIG_BYTES];
};

/** Reset a capture to empty. */
void signature_capture_init(struct signature_capture *capture);

/**
 * Feed one transcript line into the capture.
 *
 * Non-signature lines are ignored. Returns 0 always; malformed signature
 * markers latch capture->malformed instead of aborting the scan so the
 * final report can describe the failure.
 */
int signature_capture_ingest_line(struct signature_capture *capture,
				  const char *line);

/** True when header plus every pk/sig chunk arrived exactly once. */
bool signature_capture_complete(const struct signature_capture *capture);

/**
 * Verify the reassembled signature against a passport digest.
 *
 * @retval 0        Signature cryptographically valid and digest-bound.
 * @retval -EBADMSG Digest mismatch or ML-DSA verification failure.
 * @retval -EINVAL  Capture incomplete or malformed.
 */
int signature_capture_verify(const struct signature_capture *capture,
			     const char *passport_digest_hex);

#endif /* PQCP_EVIDENCE_VERIFIER_SIGNATURE_CHECK_H_ */
