/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Cryptographic transcript chain for protected-channel frames.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel.h>

#include "runtime_internal.h"

static const uint8_t transcript_domain[] = {
	'P', 'Q', 'C', 'P', '-', 'C', 'H', 'A',
	'N', 'N', 'E', 'L', '-', 'V', '1'
};

int pqcp_channel_transcript_init(
	struct pqcp_channel_transcript *transcript)
{
	if (transcript == NULL) {
		return -EINVAL;
	}
	memset(transcript, 0, sizeof(*transcript));
	transcript->schema_version =
		PQCP_CHANNEL_SCHEMA_VERSION;
	if (pqcp_runtime_internal_sha256(
		    transcript_domain,
		    sizeof(transcript_domain),
		    transcript->chaining_state) != 0) {
		return -EIO;
	}
	transcript->initialized = true;
	return 0;
}

int pqcp_channel_transcript_update(
	struct pqcp_channel_transcript *transcript,
	const uint8_t *frame,
	size_t frame_length)
{
	uint8_t length_bytes[8];
	uint8_t next[PQCP_CHANNEL_HASH_BYTES];
	const uint8_t *parts[3];
	size_t lengths[3];
	int ret;

	if (transcript == NULL || !transcript->initialized ||
	    transcript->finalized ||
	    (frame == NULL && frame_length != 0U) ||
	    frame_length == 0U ||
	    frame_length > PQCP_CHANNEL_MAX_FRAME_BYTES ||
	    UINT64_MAX - transcript->bytes < frame_length) {
		return -EINVAL;
	}
	pqcp_runtime_internal_write_u64(
		length_bytes, frame_length);
	parts[0] = transcript->chaining_state;
	lengths[0] = sizeof(transcript->chaining_state);
	parts[1] = length_bytes;
	lengths[1] = sizeof(length_bytes);
	parts[2] = frame;
	lengths[2] = frame_length;
	ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths, 3U, next);
	if (ret != 0) {
		return ret;
	}
	memcpy(transcript->chaining_state,
	       next, sizeof(next));
	memcpy(transcript->hash, next, sizeof(next));
	transcript->bytes += frame_length;
	transcript->frames++;
	pqcp_runtime_secure_zero(next, sizeof(next));
	return 0;
}

int pqcp_channel_transcript_digest(
	const struct pqcp_channel_transcript *transcript,
	uint8_t output[PQCP_CHANNEL_HASH_BYTES])
{
	if (transcript == NULL || output == NULL ||
	    !transcript->initialized ||
	    transcript->schema_version !=
		    PQCP_CHANNEL_SCHEMA_VERSION) {
		return -EINVAL;
	}
	memcpy(output, transcript->chaining_state,
	       PQCP_CHANNEL_HASH_BYTES);
	return 0;
}
