/*
 * SPDX-License-Identifier: MIT
 *
 * Signed transparency checkpoints and monotonic persistence guards.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_transparency.h>

static const uint8_t checkpoint_context[] =
	"PQCP-FLEET-TRANSPARENCY-CHECKPOINT-V1";

static bool bytes_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static bool bytes_nonzero(
	const uint8_t *value,
	size_t length)
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U; index < length; ++index) {
		aggregate |= value[index];
	}
	return aggregate != 0U;
}

static void write_be32(uint8_t output[4], uint32_t value)
{
	output[0] = (uint8_t)(value >> 24U);
	output[1] = (uint8_t)(value >> 16U);
	output[2] = (uint8_t)(value >> 8U);
	output[3] = (uint8_t)value;
}

static void write_be64(uint8_t output[8], uint64_t value)
{
	for (size_t index = 0U; index < 8U; ++index) {
		output[7U - index] =
			(uint8_t)(value >> (index * 8U));
	}
}

static int checkpoint_parts(
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	struct pqcp_fleet_transparency_part parts[8],
	uint8_t schema[4],
	uint8_t tree_size[8],
	uint8_t timestamp[8],
	uint8_t sequence[8])
{
	if (checkpoint == NULL || parts == NULL ||
	    schema == NULL || tree_size == NULL ||
	    timestamp == NULL || sequence == NULL) {
		return -EINVAL;
	}
	write_be32(schema, checkpoint->schema_version);
	write_be64(tree_size, checkpoint->tree_size);
	write_be64(timestamp, checkpoint->timestamp_ms);
	write_be64(sequence, checkpoint->sequence);
	parts[0] = (struct pqcp_fleet_transparency_part) {
		.data = checkpoint_context,
		.length = sizeof(checkpoint_context) - 1U,
	};
	parts[1] = (struct pqcp_fleet_transparency_part) {
		.data = schema,
		.length = 4U,
	};
	parts[2] = (struct pqcp_fleet_transparency_part) {
		.data = checkpoint->log_id,
		.length = sizeof(checkpoint->log_id),
	};
	parts[3] = (struct pqcp_fleet_transparency_part) {
		.data = tree_size,
		.length = 8U,
	};
	parts[4] = (struct pqcp_fleet_transparency_part) {
		.data = checkpoint->root,
		.length = sizeof(checkpoint->root),
	};
	parts[5] = (struct pqcp_fleet_transparency_part) {
		.data = timestamp,
		.length = 8U,
	};
	parts[6] = (struct pqcp_fleet_transparency_part) {
		.data = sequence,
		.length = 8U,
	};
	parts[7] = (struct pqcp_fleet_transparency_part) {
		.data = checkpoint->signer_key_id,
		.length = sizeof(checkpoint->signer_key_id),
	};
	return 0;
}

static bool checkpoint_shape_valid(
	const struct pqcp_fleet_transparency_checkpoint *checkpoint)
{
	return checkpoint != NULL &&
	       checkpoint->schema_version ==
		       PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION &&
	       checkpoint->sequence != 0U &&
	       bytes_nonzero(
		       checkpoint->log_id,
		       sizeof(checkpoint->log_id)) &&
	       bytes_nonzero(
		       checkpoint->signer_key_id,
		       sizeof(checkpoint->signer_key_id)) &&
	       checkpoint->signature != NULL &&
	       checkpoint->signature_length != 0U &&
	       checkpoint->signature_length <=
		       checkpoint->signature_capacity;
}

static int checkpoint_copy(
	struct pqcp_fleet_transparency_checkpoint *destination,
	uint8_t *signature_storage,
	size_t signature_capacity,
	const struct pqcp_fleet_transparency_checkpoint *source)
{
	if (destination == NULL || signature_storage == NULL ||
	    !checkpoint_shape_valid(source) ||
	    source->signature_length > signature_capacity) {
		return -ENOSPC;
	}
	*destination = *source;
	memcpy(signature_storage, source->signature,
	       source->signature_length);
	destination->signature = signature_storage;
	destination->signature_capacity = signature_capacity;
	return 0;
}

int pqcp_fleet_transparency_checkpoint_sign(
	const struct pqcp_fleet_transparency_snapshot *snapshot,
	uint64_t timestamp_ms,
	uint64_t sequence,
	const uint8_t signer_key_id
		[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES],
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures,
	uint8_t *signature_storage,
	size_t signature_capacity,
	struct pqcp_fleet_transparency_checkpoint *checkpoint)
{
	struct pqcp_fleet_transparency_part parts[8];
	uint8_t schema[4];
	uint8_t tree_size[8];
	uint8_t timestamp[8];
	uint8_t sequence_bytes[8];
	int ret;

	if (snapshot == NULL ||
	    snapshot->schema_version !=
		    PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION ||
	    !bytes_nonzero(
		    snapshot->log_id,
		    sizeof(snapshot->log_id)) ||
	    !bytes_nonzero(
		    snapshot->root,
		    sizeof(snapshot->root)) ||
	    sequence == 0U || signer_key_id == NULL ||
	    !bytes_nonzero(signer_key_id,
			   PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES) ||
	    hash == NULL || hash->digest == NULL ||
	    signatures == NULL || signatures->sign == NULL ||
	    signature_storage == NULL ||
	    signature_capacity == 0U || checkpoint == NULL) {
		return -EINVAL;
	}

	memset(checkpoint, 0, sizeof(*checkpoint));
	checkpoint->schema_version =
		PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	checkpoint->tree_size = snapshot->tree_size;
	checkpoint->timestamp_ms = timestamp_ms;
	checkpoint->sequence = sequence;
	memcpy(checkpoint->log_id, snapshot->log_id,
	       sizeof(checkpoint->log_id));
	memcpy(checkpoint->root, snapshot->root,
	       sizeof(checkpoint->root));
	memcpy(checkpoint->signer_key_id, signer_key_id,
	       sizeof(checkpoint->signer_key_id));
	checkpoint->signature = signature_storage;
	checkpoint->signature_capacity = signature_capacity;

	ret = checkpoint_parts(
		checkpoint, parts, schema, tree_size,
		timestamp, sequence_bytes);
	if (ret != 0) {
		goto fail;
	}
	ret = hash->digest(
		hash->context, parts,
		sizeof(parts) / sizeof(parts[0]),
		checkpoint->transcript_digest);
	if (ret != 0) {
		goto fail;
	}
	ret = signatures->sign(
		signatures->context, checkpoint->signer_key_id,
		parts, sizeof(parts) / sizeof(parts[0]),
		signature_storage, signature_capacity,
		&checkpoint->signature_length);
	if (ret != 0 ||
	    checkpoint->signature_length == 0U ||
	    checkpoint->signature_length > signature_capacity) {
		ret = ret != 0 ? ret : -EOVERFLOW;
		goto fail;
	}
	return 0;

fail:
	memset(signature_storage, 0, signature_capacity);
	memset(checkpoint, 0, sizeof(*checkpoint));
	return ret;
}

int pqcp_fleet_transparency_checkpoint_verify(
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures)
{
	struct pqcp_fleet_transparency_part parts[8];
	uint8_t calculated[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t schema[4];
	uint8_t tree_size[8];
	uint8_t timestamp[8];
	uint8_t sequence[8];
	int ret;

	if (!checkpoint_shape_valid(checkpoint) ||
	    hash == NULL || hash->digest == NULL ||
	    signatures == NULL || signatures->verify == NULL) {
		return -EINVAL;
	}
	ret = checkpoint_parts(
		checkpoint, parts, schema, tree_size,
		timestamp, sequence);
	if (ret != 0) {
		return ret;
	}
	ret = hash->digest(
		hash->context, parts,
		sizeof(parts) / sizeof(parts[0]), calculated);
	if (ret != 0) {
		return ret;
	}
	if (!bytes_equal(
		    calculated, checkpoint->transcript_digest,
		    sizeof(calculated))) {
		return -EKEYREJECTED;
	}
	return signatures->verify(
		signatures->context, checkpoint->signer_key_id,
		parts, sizeof(parts) / sizeof(parts[0]),
		checkpoint->signature,
		checkpoint->signature_length);
}

int pqcp_fleet_transparency_checkpoint_guard_init(
	struct pqcp_fleet_transparency_checkpoint_guard *guard,
	const uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES],
	const uint8_t trusted_signer_key_id
		[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES],
	uint8_t *signature_storage,
	size_t signature_capacity,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures,
	const struct pqcp_fleet_transparency_checkpoint_store_ops *persistence)
{
	bool load_present;
	bool store_present;

	if (guard == NULL || log_id == NULL ||
	    trusted_signer_key_id == NULL ||
	    !bytes_nonzero(log_id,
			   PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES) ||
	    !bytes_nonzero(
		    trusted_signer_key_id,
		    PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES) ||
	    signature_storage == NULL ||
	    signature_capacity == 0U ||
	    hash == NULL || hash->digest == NULL ||
	    signatures == NULL ||
	    signatures->verify == NULL) {
		return -EINVAL;
	}
	load_present = persistence != NULL &&
		persistence->load != NULL;
	store_present = persistence != NULL &&
		persistence->store != NULL;
	if (load_present != store_present) {
		return -EINVAL;
	}

	memset(guard, 0, sizeof(*guard));
	guard->schema_version =
		PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	memcpy(guard->log_id, log_id, sizeof(guard->log_id));
	memcpy(guard->trusted_signer_key_id,
	       trusted_signer_key_id,
	       sizeof(guard->trusted_signer_key_id));
	guard->signature_storage = signature_storage;
	guard->signature_capacity = signature_capacity;
	guard->hash = *hash;
	guard->signatures = *signatures;
	if (persistence != NULL) {
		guard->persistence = *persistence;
	}
	guard->initialized = true;
	return 0;
}

int pqcp_fleet_transparency_checkpoint_guard_restore(
	struct pqcp_fleet_transparency_checkpoint_guard *guard)
{
	int ret;

	if (guard == NULL || !guard->initialized ||
	    guard->persistence.load == NULL) {
		return -EINVAL;
	}
	memset(&guard->latest, 0, sizeof(guard->latest));
	memset(guard->signature_storage, 0,
	       guard->signature_capacity);
	ret = guard->persistence.load(
		guard->persistence.context, &guard->latest,
		guard->signature_storage,
		guard->signature_capacity);
	if (ret != 0) {
		return ret;
	}
	guard->latest.signature = guard->signature_storage;
	guard->latest.signature_capacity =
		guard->signature_capacity;
	ret = pqcp_fleet_transparency_checkpoint_verify(
		&guard->latest, &guard->hash, &guard->signatures);
	if (ret != 0 ||
	    !bytes_equal(
		    guard->latest.log_id, guard->log_id,
		    sizeof(guard->log_id)) ||
	    !bytes_equal(
		    guard->latest.signer_key_id,
		    guard->trusted_signer_key_id,
		    sizeof(guard->trusted_signer_key_id))) {
		memset(&guard->latest, 0, sizeof(guard->latest));
		memset(guard->signature_storage, 0,
		       guard->signature_capacity);
		return ret != 0 ? ret : -EKEYREJECTED;
	}
	guard->has_checkpoint = true;
	return 0;
}

static int checkpoint_growth_verify(
	const struct pqcp_fleet_transparency_checkpoint *old_checkpoint,
	const struct pqcp_fleet_transparency_checkpoint *new_checkpoint,
	const struct pqcp_fleet_transparency_consistency_proof *proof,
	const struct pqcp_fleet_transparency_hash_ops *hash)
{
	if (proof == NULL ||
	    proof->old_tree_size != old_checkpoint->tree_size ||
	    proof->new_tree_size != new_checkpoint->tree_size ||
	    !bytes_equal(
		    proof->old_root, old_checkpoint->root,
		    sizeof(proof->old_root)) ||
	    !bytes_equal(
		    proof->new_root, new_checkpoint->root,
		    sizeof(proof->new_root))) {
		return -EBADMSG;
	}
	return pqcp_fleet_transparency_consistency_proof_verify(
		hash, proof);
}

int pqcp_fleet_transparency_checkpoint_guard_accept(
	struct pqcp_fleet_transparency_checkpoint_guard *guard,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	const struct pqcp_fleet_transparency_consistency_proof *consistency)
{
	struct pqcp_fleet_transparency_checkpoint prepared;
	int ret;

	if (guard == NULL || !guard->initialized ||
	    checkpoint == NULL) {
		return -EINVAL;
	}
	ret = pqcp_fleet_transparency_checkpoint_verify(
		checkpoint, &guard->hash, &guard->signatures);
	if (ret != 0) {
		return ret;
	}
	if (!bytes_equal(
		    checkpoint->log_id, guard->log_id,
		    sizeof(guard->log_id)) ||
	    !bytes_equal(
		    checkpoint->signer_key_id,
		    guard->trusted_signer_key_id,
		    sizeof(guard->trusted_signer_key_id))) {
		return -EKEYREJECTED;
	}
	if (checkpoint->signature_length >
	    guard->signature_capacity) {
		return -ENOSPC;
	}

	if (guard->has_checkpoint) {
		if (checkpoint->tree_size <
		    guard->latest.tree_size ||
		    checkpoint->timestamp_ms <
			    guard->latest.timestamp_ms) {
			return -ESTALE;
		}
		if (checkpoint->sequence <=
		    guard->latest.sequence) {
			return -EALREADY;
		}
		if (checkpoint->tree_size ==
		    guard->latest.tree_size) {
			if (!bytes_equal(
				    checkpoint->root,
				    guard->latest.root,
				    sizeof(checkpoint->root))) {
				return -EKEYREJECTED;
			}
		} else {
			ret = checkpoint_growth_verify(
				&guard->latest, checkpoint,
				consistency, &guard->hash);
			if (ret != 0) {
				return ret;
			}
		}
	}

	memset(&prepared, 0, sizeof(prepared));
	prepared = *checkpoint;
	if (guard->persistence.store != NULL) {
		ret = guard->persistence.store(
			guard->persistence.context, checkpoint);
		if (ret != 0) {
			return ret;
		}
	}
	ret = checkpoint_copy(
		&guard->latest, guard->signature_storage,
		guard->signature_capacity, &prepared);
	if (ret != 0) {
		return ret;
	}
	guard->has_checkpoint = true;
	return 0;
}
