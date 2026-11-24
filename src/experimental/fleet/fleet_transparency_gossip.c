/*
 * SPDX-License-Identifier: MIT
 *
 * Signed checkpoint gossip and split-view detection.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_transparency.h>

static const uint8_t gossip_context[] =
	"PQCP-FLEET-TRANSPARENCY-GOSSIP-V1";
static const uint8_t evidence_context[] =
	"PQCP-FLEET-TRANSPARENCY-EVIDENCE-V1";

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

static bool peer_valid(
	const struct pqcp_fleet_transparency_gossip_peer *peer)
{
	return peer != NULL &&
	       peer->schema_version ==
		       PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION &&
	       peer->generation != 0U &&
	       peer->expires_at_ms > peer->not_before_ms &&
	       bytes_nonzero(peer->peer_id,
			     sizeof(peer->peer_id)) &&
	       bytes_nonzero(peer->key_id,
			     sizeof(peer->key_id)) &&
	       peer->state >=
		       PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_ACTIVE &&
	       peer->state <=
		       PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_REVOKED;
}

static bool monitor_valid(
	const struct pqcp_fleet_transparency_gossip_monitor *monitor)
{
	return monitor != NULL && monitor->initialized &&
	       monitor->schema_version ==
		       PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION &&
	       monitor->generation != 0U &&
	       monitor->peers != NULL && monitor->capacity != 0U &&
	       monitor->hash.digest != NULL &&
	       monitor->signatures.verify != NULL;
}

static int peer_index(
	const struct pqcp_fleet_transparency_gossip_monitor *monitor,
	const uint8_t peer_id
		[PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES])
{
	for (size_t index = 0U; index < monitor->capacity; ++index) {
		if (monitor->peers[index].state !=
			    PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_EMPTY &&
		    bytes_equal(
			    monitor->peers[index].peer_id, peer_id,
			    PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES)) {
			return (int)index;
		}
	}
	return -1;
}

static int free_index(
	const struct pqcp_fleet_transparency_gossip_monitor *monitor)
{
	for (size_t index = 0U; index < monitor->capacity; ++index) {
		if (monitor->peers[index].state ==
		    PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_EMPTY) {
			return (int)index;
		}
	}
	return -1;
}

static int message_parts(
	const struct pqcp_fleet_transparency_gossip_message *message,
	struct pqcp_fleet_transparency_part parts[10],
	uint8_t schema[4],
	uint8_t generation[4],
	uint8_t tree_size[8],
	uint8_t sent_at[8],
	uint8_t sequence[8])
{
	if (message == NULL) {
		return -EINVAL;
	}
	write_be32(schema, message->schema_version);
	write_be32(generation, message->peer_generation);
	write_be64(tree_size, message->tree_size);
	write_be64(sent_at, message->sent_at_ms);
	write_be64(sequence, message->sequence);
	parts[0] = (struct pqcp_fleet_transparency_part) {
		.data = gossip_context,
		.length = sizeof(gossip_context) - 1U,
	};
	parts[1] = (struct pqcp_fleet_transparency_part) {
		.data = schema, .length = 4U,
	};
	parts[2] = (struct pqcp_fleet_transparency_part) {
		.data = message->peer_id,
		.length = sizeof(message->peer_id),
	};
	parts[3] = (struct pqcp_fleet_transparency_part) {
		.data = generation, .length = 4U,
	};
	parts[4] = (struct pqcp_fleet_transparency_part) {
		.data = message->log_id,
		.length = sizeof(message->log_id),
	};
	parts[5] = (struct pqcp_fleet_transparency_part) {
		.data = tree_size, .length = 8U,
	};
	parts[6] = (struct pqcp_fleet_transparency_part) {
		.data = message->root,
		.length = sizeof(message->root),
	};
	parts[7] = (struct pqcp_fleet_transparency_part) {
		.data = message->checkpoint_digest,
		.length = sizeof(message->checkpoint_digest),
	};
	parts[8] = (struct pqcp_fleet_transparency_part) {
		.data = sent_at, .length = 8U,
	};
	parts[9] = (struct pqcp_fleet_transparency_part) {
		.data = sequence, .length = 8U,
	};
	return 0;
}

static int message_verify(
	const struct pqcp_fleet_transparency_gossip_message *message,
	const struct pqcp_fleet_transparency_gossip_peer *peer,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures)
{
	struct pqcp_fleet_transparency_part parts[10];
	uint8_t calculated[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t schema[4];
	uint8_t generation[4];
	uint8_t tree_size[8];
	uint8_t sent_at[8];
	uint8_t sequence[8];
	int ret;

	if (message == NULL ||
	    message->schema_version !=
		    PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION ||
	    message->peer_generation == 0U ||
	    message->sequence == 0U ||
	    message->signature == NULL ||
	    message->signature_length == 0U ||
	    message->signature_length >
		    message->signature_capacity ||
	    !bytes_nonzero(message->root,
			   sizeof(message->root)) ||
	    !bytes_nonzero(
		    message->checkpoint_digest,
		    sizeof(message->checkpoint_digest)) ||
	    !peer_valid(peer) ||
	    !bytes_equal(
		    message->peer_id, peer->peer_id,
		    sizeof(message->peer_id)) ||
	    message->peer_generation != peer->generation) {
		return -EINVAL;
	}
	ret = message_parts(
		message, parts, schema, generation,
		tree_size, sent_at, sequence);
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
		    calculated, message->transcript_digest,
		    sizeof(calculated))) {
		return -EKEYREJECTED;
	}
	return signatures->verify(
		signatures->context, peer->key_id,
		parts, sizeof(parts) / sizeof(parts[0]),
		message->signature, message->signature_length);
}

static int evidence_digest(
	struct pqcp_fleet_transparency_evidence *evidence,
	const struct pqcp_fleet_transparency_hash_ops *hash)
{
	struct pqcp_fleet_transparency_part parts[13];
	uint8_t schema[4];
	uint8_t kind[4];
	uint8_t detected[8];
	uint8_t first_size[8];
	uint8_t second_size[8];
	uint8_t first_sequence[8];
	uint8_t second_sequence[8];

	write_be32(schema, evidence->schema_version);
	write_be32(kind, (uint32_t)evidence->kind);
	write_be64(detected, evidence->detected_at_ms);
	write_be64(first_size, evidence->first_tree_size);
	write_be64(second_size, evidence->second_tree_size);
	write_be64(first_sequence, evidence->first_sequence);
	write_be64(second_sequence, evidence->second_sequence);
	parts[0] = (struct pqcp_fleet_transparency_part) {
		.data = evidence_context,
		.length = sizeof(evidence_context) - 1U,
	};
	parts[1] = (struct pqcp_fleet_transparency_part) {
		.data = schema, .length = sizeof(schema),
	};
	parts[2] = (struct pqcp_fleet_transparency_part) {
		.data = kind, .length = sizeof(kind),
	};
	parts[3] = (struct pqcp_fleet_transparency_part) {
		.data = detected, .length = sizeof(detected),
	};
	parts[4] = (struct pqcp_fleet_transparency_part) {
		.data = evidence->participant_id,
		.length = sizeof(evidence->participant_id),
	};
	parts[5] = (struct pqcp_fleet_transparency_part) {
		.data = first_size, .length = sizeof(first_size),
	};
	parts[6] = (struct pqcp_fleet_transparency_part) {
		.data = second_size, .length = sizeof(second_size),
	};
	parts[7] = (struct pqcp_fleet_transparency_part) {
		.data = evidence->first_root,
		.length = sizeof(evidence->first_root),
	};
	parts[8] = (struct pqcp_fleet_transparency_part) {
		.data = evidence->second_root,
		.length = sizeof(evidence->second_root),
	};
	parts[9] = (struct pqcp_fleet_transparency_part) {
		.data = first_sequence,
		.length = sizeof(first_sequence),
	};
	parts[10] = (struct pqcp_fleet_transparency_part) {
		.data = second_sequence,
		.length = sizeof(second_sequence),
	};
	parts[11] = (struct pqcp_fleet_transparency_part) {
		.data = evidence->first_statement_digest,
		.length = sizeof(evidence->first_statement_digest),
	};
	parts[12] = (struct pqcp_fleet_transparency_part) {
		.data = evidence->second_statement_digest,
		.length = sizeof(evidence->second_statement_digest),
	};
	return hash->digest(
		hash->context, parts,
		sizeof(parts) / sizeof(parts[0]),
		evidence->evidence_digest);
}

static int evidence_set(
	struct pqcp_fleet_transparency_evidence *evidence,
	enum pqcp_fleet_transparency_evidence_kind kind,
	const uint8_t participant_id
		[PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES],
	uint64_t first_size,
	const uint8_t first_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	uint64_t first_sequence,
	const uint8_t first_digest
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	uint64_t second_size,
	const uint8_t second_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	uint64_t second_sequence,
	const uint8_t second_digest
		[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	uint64_t now_ms,
	const struct pqcp_fleet_transparency_hash_ops *hash)
{
	if (evidence == NULL) {
		return 0;
	}
	memset(evidence, 0, sizeof(*evidence));
	evidence->schema_version =
		PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	evidence->kind = kind;
	evidence->detected_at_ms = now_ms;
	evidence->first_tree_size = first_size;
	evidence->second_tree_size = second_size;
	evidence->first_sequence = first_sequence;
	evidence->second_sequence = second_sequence;
	memcpy(evidence->participant_id, participant_id,
	       sizeof(evidence->participant_id));
	memcpy(evidence->first_root, first_root,
	       sizeof(evidence->first_root));
	memcpy(evidence->second_root, second_root,
	       sizeof(evidence->second_root));
	memcpy(evidence->first_statement_digest, first_digest,
	       sizeof(evidence->first_statement_digest));
	memcpy(evidence->second_statement_digest, second_digest,
	       sizeof(evidence->second_statement_digest));
	return evidence_digest(evidence, hash);
}

int pqcp_fleet_transparency_gossip_monitor_init(
	struct pqcp_fleet_transparency_gossip_monitor *monitor,
	const uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES],
	struct pqcp_fleet_transparency_gossip_peer *peers,
	size_t capacity,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures)
{
	if (monitor == NULL || log_id == NULL ||
	    !bytes_nonzero(log_id,
			   PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES) ||
	    peers == NULL || capacity == 0U ||
	    hash == NULL || hash->digest == NULL ||
	    signatures == NULL ||
	    signatures->verify == NULL) {
		return -EINVAL;
	}
	memset(monitor, 0, sizeof(*monitor));
	memset(peers, 0, capacity * sizeof(*peers));
	monitor->schema_version =
		PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	monitor->generation = 1U;
	memcpy(monitor->log_id, log_id,
	       sizeof(monitor->log_id));
	monitor->peers = peers;
	monitor->capacity = capacity;
	monitor->hash = *hash;
	monitor->signatures = *signatures;
	monitor->initialized = true;
	return 0;
}

int pqcp_fleet_transparency_gossip_peer_upsert(
	struct pqcp_fleet_transparency_gossip_monitor *monitor,
	const struct pqcp_fleet_transparency_gossip_peer *peer)
{
	int index;

	if (!monitor_valid(monitor) || !peer_valid(peer) ||
	    peer->state ==
		    PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_EMPTY ||
	    peer->has_summary ||
	    monitor->generation == UINT64_MAX) {
		return -EINVAL;
	}
	index = peer_index(monitor, peer->peer_id);
	if (index >= 0) {
		if (peer->generation <=
		    monitor->peers[index].generation) {
			return -ESTALE;
		}
	} else {
		index = free_index(monitor);
		if (index < 0) {
			return -ENOSPC;
		}
	}
	monitor->peers[index] = *peer;
	monitor->peers[index].has_summary = false;
	++monitor->generation;
	return 0;
}

int pqcp_fleet_transparency_gossip_message_sign(
	const struct pqcp_fleet_transparency_gossip_peer *peer,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	uint64_t sent_at_ms,
	uint64_t sequence,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures,
	uint8_t *signature_storage,
	size_t signature_capacity,
	struct pqcp_fleet_transparency_gossip_message *message)
{
	struct pqcp_fleet_transparency_part parts[10];
	uint8_t schema[4];
	uint8_t generation[4];
	uint8_t tree_size[8];
	uint8_t sent_at[8];
	uint8_t sequence_bytes[8];
	int ret;

	if (!peer_valid(peer) ||
	    peer->state !=
		    PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_ACTIVE ||
	    checkpoint == NULL ||
	    sent_at_ms < peer->not_before_ms ||
	    sent_at_ms >= peer->expires_at_ms ||
	    sequence == 0U || hash == NULL ||
	    hash->digest == NULL || signatures == NULL ||
	    signatures->sign == NULL ||
	    signature_storage == NULL ||
	    signature_capacity == 0U || message == NULL) {
		return -EINVAL;
	}
	memset(message, 0, sizeof(*message));
	message->schema_version =
		PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	message->peer_generation = peer->generation;
	message->tree_size = checkpoint->tree_size;
	message->sent_at_ms = sent_at_ms;
	message->sequence = sequence;
	memcpy(message->peer_id, peer->peer_id,
	       sizeof(message->peer_id));
	memcpy(message->log_id, checkpoint->log_id,
	       sizeof(message->log_id));
	memcpy(message->root, checkpoint->root,
	       sizeof(message->root));
	memcpy(message->checkpoint_digest,
	       checkpoint->transcript_digest,
	       sizeof(message->checkpoint_digest));
	message->signature = signature_storage;
	message->signature_capacity = signature_capacity;
	ret = message_parts(
		message, parts, schema, generation,
		tree_size, sent_at, sequence_bytes);
	if (ret != 0) {
		goto fail;
	}
	ret = hash->digest(
		hash->context, parts,
		sizeof(parts) / sizeof(parts[0]),
		message->transcript_digest);
	if (ret != 0) {
		goto fail;
	}
	ret = signatures->sign(
		signatures->context, peer->key_id,
		parts, sizeof(parts) / sizeof(parts[0]),
		signature_storage, signature_capacity,
		&message->signature_length);
	if (ret != 0 || message->signature_length == 0U ||
	    message->signature_length > signature_capacity) {
		ret = ret != 0 ? ret : -EOVERFLOW;
		goto fail;
	}
	return 0;

fail:
	memset(signature_storage, 0, signature_capacity);
	memset(message, 0, sizeof(*message));
	return ret;
}

static int proof_for_growth(
	uint64_t old_size,
	const uint8_t old_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	uint64_t new_size,
	const uint8_t new_root[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES],
	const struct pqcp_fleet_transparency_consistency_proof *proof,
	const struct pqcp_fleet_transparency_hash_ops *hash)
{
	if (proof == NULL ||
	    proof->old_tree_size != old_size ||
	    proof->new_tree_size != new_size ||
	    !bytes_equal(
		    proof->old_root, old_root,
		    sizeof(proof->old_root)) ||
	    !bytes_equal(
		    proof->new_root, new_root,
		    sizeof(proof->new_root))) {
		return -EBADMSG;
	}
	return pqcp_fleet_transparency_consistency_proof_verify(
		hash, proof);
}

int pqcp_fleet_transparency_gossip_submit(
	struct pqcp_fleet_transparency_gossip_monitor *monitor,
	const struct pqcp_fleet_transparency_gossip_message *message,
	const struct pqcp_fleet_transparency_consistency_proof *consistency,
	uint64_t received_at_ms,
	struct pqcp_fleet_transparency_evidence *evidence)
{
	struct pqcp_fleet_transparency_gossip_peer *peer;
	int index;
	int ret;

	if (!monitor_valid(monitor) || message == NULL ||
	    message->sent_at_ms > received_at_ms ||
	    monitor->generation == UINT64_MAX) {
		return -EINVAL;
	}
	if (evidence != NULL) {
		memset(evidence, 0, sizeof(*evidence));
	}
	if (!bytes_equal(
		    message->log_id, monitor->log_id,
		    sizeof(monitor->log_id))) {
		return -EKEYREJECTED;
	}
	index = peer_index(monitor, message->peer_id);
	if (index < 0) {
		return -ENOENT;
	}
	peer = &monitor->peers[index];
	if (peer->state !=
		    PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_ACTIVE ||
	    message->sent_at_ms < peer->not_before_ms ||
	    message->sent_at_ms >= peer->expires_at_ms) {
		return -EKEYREVOKED;
	}
	ret = message_verify(
		message, peer, &monitor->hash,
		&monitor->signatures);
	if (ret != 0) {
		return ret;
	}

	if (peer->has_summary) {
		if (message->sequence <= peer->latest_sequence) {
			(void)evidence_set(
				evidence,
				PQCP_FLEET_TRANSPARENCY_EVIDENCE_REPLAY,
				message->peer_id,
				peer->latest_tree_size,
				peer->latest_root,
				peer->latest_sequence,
				peer->latest_message_digest,
				message->tree_size, message->root,
				message->sequence,
				message->transcript_digest,
				received_at_ms, &monitor->hash);
			return -EALREADY;
		}
		if (message->tree_size < peer->latest_tree_size) {
			(void)evidence_set(
				evidence,
				PQCP_FLEET_TRANSPARENCY_EVIDENCE_ROLLBACK,
				message->peer_id,
				peer->latest_tree_size,
				peer->latest_root,
				peer->latest_sequence,
				peer->latest_message_digest,
				message->tree_size, message->root,
				message->sequence,
				message->transcript_digest,
				received_at_ms, &monitor->hash);
			return -ESTALE;
		}
		if (message->tree_size == peer->latest_tree_size) {
			if (!bytes_equal(
				    message->root, peer->latest_root,
				    sizeof(message->root))) {
				(void)evidence_set(
					evidence,
					PQCP_FLEET_TRANSPARENCY_EVIDENCE_EQUIVOCATION,
					message->peer_id,
					peer->latest_tree_size,
					peer->latest_root,
					peer->latest_sequence,
					peer->latest_message_digest,
					message->tree_size,
					message->root,
					message->sequence,
					message->transcript_digest,
					received_at_ms,
					&monitor->hash);
				return -EKEYREJECTED;
			}
		} else {
			ret = proof_for_growth(
				peer->latest_tree_size,
				peer->latest_root,
				message->tree_size, message->root,
				consistency, &monitor->hash);
			if (ret != 0) {
				(void)evidence_set(
					evidence,
					PQCP_FLEET_TRANSPARENCY_EVIDENCE_INCONSISTENT_GROWTH,
					message->peer_id,
					peer->latest_tree_size,
					peer->latest_root,
					peer->latest_sequence,
					peer->latest_message_digest,
					message->tree_size,
					message->root,
					message->sequence,
					message->transcript_digest,
					received_at_ms,
					&monitor->hash);
				return ret;
			}
		}
	}

	for (size_t other = 0U;
	     other < monitor->capacity;
	     ++other) {
		const struct pqcp_fleet_transparency_gossip_peer *candidate =
			&monitor->peers[other];

		if (other == (size_t)index ||
		    !candidate->has_summary) {
			continue;
		}
		if (candidate->latest_tree_size ==
			    message->tree_size &&
		    !bytes_equal(
			    candidate->latest_root, message->root,
			    sizeof(message->root))) {
			(void)evidence_set(
				evidence,
				PQCP_FLEET_TRANSPARENCY_EVIDENCE_EQUIVOCATION,
				message->peer_id,
				candidate->latest_tree_size,
				candidate->latest_root,
				candidate->latest_sequence,
				candidate->latest_message_digest,
				message->tree_size, message->root,
				message->sequence,
				message->transcript_digest,
				received_at_ms, &monitor->hash);
			return -EKEYREJECTED;
		}
	}

	peer->latest_tree_size = message->tree_size;
	peer->latest_sequence = message->sequence;
	peer->latest_received_at_ms = received_at_ms;
	memcpy(peer->latest_root, message->root,
	       sizeof(peer->latest_root));
	memcpy(peer->latest_checkpoint_digest,
	       message->checkpoint_digest,
	       sizeof(peer->latest_checkpoint_digest));
	memcpy(peer->latest_message_digest,
	       message->transcript_digest,
	       sizeof(peer->latest_message_digest));
	peer->has_summary = true;
	++monitor->generation;
	return 0;
}

int pqcp_fleet_transparency_gossip_compare(
	const struct pqcp_fleet_transparency_gossip_monitor *monitor,
	const struct pqcp_fleet_transparency_checkpoint *local,
	const struct pqcp_fleet_transparency_consistency_proof *consistency,
	uint64_t now_ms,
	struct pqcp_fleet_transparency_evidence *evidence)
{
	uint8_t local_statement[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	int ret;

	if (!monitor_valid(monitor) || local == NULL ||
	    !bytes_equal(
		    local->log_id, monitor->log_id,
		    sizeof(monitor->log_id))) {
		return -EINVAL;
	}
	ret = pqcp_fleet_transparency_checkpoint_verify(
		local, &monitor->hash, &monitor->signatures);
	if (ret != 0) {
		return ret;
	}
	if (evidence != NULL) {
		memset(evidence, 0, sizeof(*evidence));
	}
	memcpy(local_statement, local->transcript_digest,
	       sizeof(local_statement));
	for (size_t index = 0U;
	     index < monitor->capacity;
	     ++index) {
		const struct pqcp_fleet_transparency_gossip_peer *peer =
			&monitor->peers[index];

		if (peer->state !=
			    PQCP_FLEET_TRANSPARENCY_GOSSIP_PEER_ACTIVE ||
		    !peer->has_summary) {
			continue;
		}
		if (peer->latest_tree_size == local->tree_size) {
			if (bytes_equal(
				    peer->latest_root, local->root,
				    sizeof(local->root))) {
				continue;
			}
			(void)evidence_set(
				evidence,
				PQCP_FLEET_TRANSPARENCY_EVIDENCE_EQUIVOCATION,
				peer->peer_id,
				peer->latest_tree_size,
				peer->latest_root,
				peer->latest_sequence,
				peer->latest_message_digest,
				local->tree_size, local->root,
				local->sequence, local_statement,
				now_ms, &monitor->hash);
			return -EKEYREJECTED;
		}
		if (peer->latest_tree_size < local->tree_size) {
			ret = proof_for_growth(
				peer->latest_tree_size,
				peer->latest_root,
				local->tree_size, local->root,
				consistency, &monitor->hash);
		} else {
			ret = proof_for_growth(
				local->tree_size, local->root,
				peer->latest_tree_size,
				peer->latest_root,
				consistency, &monitor->hash);
		}
		if (ret != 0) {
			(void)evidence_set(
				evidence,
				PQCP_FLEET_TRANSPARENCY_EVIDENCE_INCONSISTENT_GROWTH,
				peer->peer_id,
				peer->latest_tree_size,
				peer->latest_root,
				peer->latest_sequence,
				peer->latest_message_digest,
				local->tree_size, local->root,
				local->sequence, local_statement,
				now_ms, &monitor->hash);
			return ret;
		}
	}
	return 0;
}
