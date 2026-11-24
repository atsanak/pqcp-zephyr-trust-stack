/*
 * SPDX-License-Identifier: MIT
 *
 * Independent checkpoint witnesses and bounded quorum evaluation.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_transparency.h>

static const uint8_t witness_context[] =
	"PQCP-FLEET-TRANSPARENCY-WITNESS-V1";
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

static bool authority_valid(
	const struct pqcp_fleet_transparency_witness_authority *authority)
{
	const uint32_t known_roles =
		PQCP_FLEET_TRANSPARENCY_WITNESS_OPERATOR |
		PQCP_FLEET_TRANSPARENCY_WITNESS_AUDITOR |
		PQCP_FLEET_TRANSPARENCY_WITNESS_VENDOR |
		PQCP_FLEET_TRANSPARENCY_WITNESS_REGULATOR |
		PQCP_FLEET_TRANSPARENCY_WITNESS_DEVICE;

	return authority != NULL &&
	       authority->schema_version ==
		       PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION &&
	       authority->generation != 0U &&
	       authority->roles != 0U &&
	       (authority->roles & ~known_roles) == 0U &&
	       authority->weight != 0U &&
	       authority->expires_at_ms > authority->not_before_ms &&
	       bytes_nonzero(
		       authority->witness_id,
		       sizeof(authority->witness_id)) &&
	       bytes_nonzero(
		       authority->key_id,
		       sizeof(authority->key_id)) &&
	       authority->state >=
		       PQCP_FLEET_TRANSPARENCY_WITNESS_ACTIVE &&
	       authority->state <=
		       PQCP_FLEET_TRANSPARENCY_WITNESS_REVOKED &&
	       (authority->state ==
			PQCP_FLEET_TRANSPARENCY_WITNESS_REVOKED ?
			authority->revoked_at_ms != 0U :
			authority->revoked_at_ms == 0U);
}

static bool registry_valid(
	const struct pqcp_fleet_transparency_witness_registry *registry)
{
	return registry != NULL && registry->initialized &&
	       registry->schema_version ==
		       PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION &&
	       registry->records != NULL &&
	       registry->capacity != 0U &&
	       registry->signature_arena != NULL &&
	       registry->signature_stride != 0U &&
	       registry->hash.digest != NULL &&
	       registry->signatures.verify != NULL;
}

static int record_index(
	const struct pqcp_fleet_transparency_witness_registry *registry,
	const uint8_t witness_id
		[PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES])
{
	for (size_t index = 0U; index < registry->capacity; ++index) {
		if (registry->records[index].authority.state !=
			    PQCP_FLEET_TRANSPARENCY_WITNESS_EMPTY &&
		    bytes_equal(
			    registry->records[index].authority.witness_id,
			    witness_id,
			    PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES)) {
			return (int)index;
		}
	}
	return -1;
}

static int free_index(
	const struct pqcp_fleet_transparency_witness_registry *registry)
{
	for (size_t index = 0U; index < registry->capacity; ++index) {
		if (registry->records[index].authority.state ==
		    PQCP_FLEET_TRANSPARENCY_WITNESS_EMPTY) {
			return (int)index;
		}
	}
	return -1;
}

static uint8_t *record_signature(
	const struct pqcp_fleet_transparency_witness_registry *registry,
	size_t index)
{
	return registry->signature_arena +
		index * registry->signature_stride;
}

static int statement_parts(
	const struct pqcp_fleet_transparency_witness_statement *statement,
	struct pqcp_fleet_transparency_part parts[7],
	uint8_t schema[4],
	uint8_t generation[4],
	uint8_t observed_at[8],
	uint8_t sequence[8])
{
	if (statement == NULL) {
		return -EINVAL;
	}
	write_be32(schema, statement->schema_version);
	write_be32(generation, statement->authority_generation);
	write_be64(observed_at, statement->observed_at_ms);
	write_be64(sequence, statement->sequence);
	parts[0] = (struct pqcp_fleet_transparency_part) {
		.data = witness_context,
		.length = sizeof(witness_context) - 1U,
	};
	parts[1] = (struct pqcp_fleet_transparency_part) {
		.data = schema,
		.length = 4U,
	};
	parts[2] = (struct pqcp_fleet_transparency_part) {
		.data = statement->witness_id,
		.length = sizeof(statement->witness_id),
	};
	parts[3] = (struct pqcp_fleet_transparency_part) {
		.data = generation,
		.length = 4U,
	};
	parts[4] = (struct pqcp_fleet_transparency_part) {
		.data = statement->checkpoint_digest,
		.length = sizeof(statement->checkpoint_digest),
	};
	parts[5] = (struct pqcp_fleet_transparency_part) {
		.data = observed_at,
		.length = 8U,
	};
	parts[6] = (struct pqcp_fleet_transparency_part) {
		.data = sequence,
		.length = 8U,
	};
	return 0;
}

static int statement_verify(
	const struct pqcp_fleet_transparency_witness_statement *statement,
	const struct pqcp_fleet_transparency_witness_authority *authority,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures)
{
	struct pqcp_fleet_transparency_part parts[7];
	uint8_t calculated[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t schema[4];
	uint8_t generation[4];
	uint8_t observed_at[8];
	uint8_t sequence[8];
	int ret;

	if (statement == NULL ||
	    statement->schema_version !=
		    PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION ||
	    statement->authority_generation == 0U ||
	    statement->sequence == 0U ||
	    statement->signature == NULL ||
	    statement->signature_length == 0U ||
	    statement->signature_length >
		    statement->signature_capacity ||
	    !authority_valid(authority) ||
	    !bytes_equal(
		    statement->witness_id, authority->witness_id,
		    sizeof(statement->witness_id)) ||
	    statement->authority_generation !=
		    authority->generation ||
	    hash == NULL || hash->digest == NULL ||
	    signatures == NULL ||
	    signatures->verify == NULL) {
		return -EINVAL;
	}
	ret = statement_parts(
		statement, parts, schema, generation,
		observed_at, sequence);
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
		    calculated, statement->transcript_digest,
		    sizeof(calculated))) {
		return -EKEYREJECTED;
	}
	return signatures->verify(
		signatures->context, authority->key_id,
		parts, sizeof(parts) / sizeof(parts[0]),
		statement->signature,
		statement->signature_length);
}

static int evidence_finalize(
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
	const struct pqcp_fleet_transparency_witness_record *record,
	const struct pqcp_fleet_transparency_witness_statement *statement,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
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
	evidence->first_tree_size = record->latest_tree_size;
	evidence->second_tree_size = checkpoint->tree_size;
	evidence->first_sequence = record->latest_sequence;
	evidence->second_sequence = statement->sequence;
	memcpy(evidence->participant_id,
	       statement->witness_id,
	       sizeof(evidence->participant_id));
	memcpy(evidence->first_root, record->latest_root,
	       sizeof(evidence->first_root));
	memcpy(evidence->second_root, checkpoint->root,
	       sizeof(evidence->second_root));
	memcpy(evidence->first_statement_digest,
	       record->latest_statement_digest,
	       sizeof(evidence->first_statement_digest));
	memcpy(evidence->second_statement_digest,
	       statement->transcript_digest,
	       sizeof(evidence->second_statement_digest));
	return evidence_finalize(evidence, hash);
}

int pqcp_fleet_transparency_witness_registry_init(
	struct pqcp_fleet_transparency_witness_registry *registry,
	const uint8_t log_id[PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES],
	const uint8_t trusted_log_key_id
		[PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES],
	struct pqcp_fleet_transparency_witness_record *records,
	size_t capacity,
	uint8_t *signature_arena,
	size_t signature_stride,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures)
{
	if (registry == NULL || log_id == NULL ||
	    trusted_log_key_id == NULL ||
	    !bytes_nonzero(log_id,
			   PQCP_FLEET_TRANSPARENCY_LOG_ID_BYTES) ||
	    !bytes_nonzero(
		    trusted_log_key_id,
		    PQCP_FLEET_TRANSPARENCY_KEY_ID_BYTES) ||
	    records == NULL || capacity == 0U ||
	    signature_arena == NULL ||
	    signature_stride == 0U ||
	    capacity > SIZE_MAX / signature_stride ||
	    hash == NULL || hash->digest == NULL ||
	    signatures == NULL ||
	    signatures->verify == NULL) {
		return -EINVAL;
	}
	memset(registry, 0, sizeof(*registry));
	memset(records, 0, capacity * sizeof(*records));
	memset(signature_arena, 0, capacity * signature_stride);
	registry->schema_version =
		PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	registry->generation = 1U;
	memcpy(registry->log_id, log_id,
	       sizeof(registry->log_id));
	memcpy(registry->trusted_log_key_id,
	       trusted_log_key_id,
	       sizeof(registry->trusted_log_key_id));
	registry->records = records;
	registry->capacity = capacity;
	registry->signature_arena = signature_arena;
	registry->signature_stride = signature_stride;
	registry->hash = *hash;
	registry->signatures = *signatures;
	registry->initialized = true;
	return 0;
}

int pqcp_fleet_transparency_witness_upsert(
	struct pqcp_fleet_transparency_witness_registry *registry,
	const struct pqcp_fleet_transparency_witness_authority *authority)
{
	int index;

	if (!registry_valid(registry) ||
	    !authority_valid(authority) ||
	    authority->state ==
		    PQCP_FLEET_TRANSPARENCY_WITNESS_EMPTY ||
	    registry->generation == UINT64_MAX) {
		return -EINVAL;
	}
	index = record_index(registry, authority->witness_id);
	if (index >= 0) {
		if (authority->generation <=
		    registry->records[index].authority.generation) {
			return -ESTALE;
		}
	} else {
		index = free_index(registry);
		if (index < 0) {
			return -ENOSPC;
		}
	}
	memset(&registry->records[index], 0,
	       sizeof(registry->records[index]));
	memset(record_signature(registry, (size_t)index), 0,
	       registry->signature_stride);
	registry->records[index].authority = *authority;
	++registry->generation;
	return 0;
}

int pqcp_fleet_transparency_witness_revoke(
	struct pqcp_fleet_transparency_witness_registry *registry,
	const uint8_t witness_id
		[PQCP_FLEET_TRANSPARENCY_PARTICIPANT_ID_BYTES],
	uint64_t revoked_at_ms)
{
	int index;

	if (!registry_valid(registry) || witness_id == NULL ||
	    revoked_at_ms == 0U ||
	    registry->generation == UINT64_MAX) {
		return -EINVAL;
	}
	index = record_index(registry, witness_id);
	if (index < 0) {
		return -ENOENT;
	}
	if (registry->records[index].authority.state ==
	    PQCP_FLEET_TRANSPARENCY_WITNESS_REVOKED) {
		return -EALREADY;
	}
	if (registry->records[index].authority.generation ==
	    UINT32_MAX) {
		return -EOVERFLOW;
	}
	registry->records[index].authority.state =
		PQCP_FLEET_TRANSPARENCY_WITNESS_REVOKED;
	registry->records[index].authority.revoked_at_ms =
		revoked_at_ms;
	++registry->records[index].authority.generation;
	++registry->generation;
	return 0;
}

int pqcp_fleet_transparency_witness_statement_sign(
	const struct pqcp_fleet_transparency_witness_authority *authority,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	uint64_t observed_at_ms,
	uint64_t sequence,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures,
	uint8_t *signature_storage,
	size_t signature_capacity,
	struct pqcp_fleet_transparency_witness_statement *statement)
{
	struct pqcp_fleet_transparency_part parts[7];
	uint8_t schema[4];
	uint8_t generation[4];
	uint8_t observed_at[8];
	uint8_t sequence_bytes[8];
	int ret;

	if (!authority_valid(authority) ||
	    authority->state !=
		    PQCP_FLEET_TRANSPARENCY_WITNESS_ACTIVE ||
	    checkpoint == NULL ||
	    observed_at_ms < authority->not_before_ms ||
	    observed_at_ms >= authority->expires_at_ms ||
	    sequence == 0U || hash == NULL ||
	    hash->digest == NULL || signatures == NULL ||
	    signatures->sign == NULL ||
	    signature_storage == NULL ||
	    signature_capacity == 0U || statement == NULL) {
		return -EINVAL;
	}
	memset(statement, 0, sizeof(*statement));
	statement->schema_version =
		PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	statement->authority_generation =
		authority->generation;
	statement->observed_at_ms = observed_at_ms;
	statement->sequence = sequence;
	memcpy(statement->witness_id, authority->witness_id,
	       sizeof(statement->witness_id));
	memcpy(statement->checkpoint_digest,
	       checkpoint->transcript_digest,
	       sizeof(statement->checkpoint_digest));
	statement->signature = signature_storage;
	statement->signature_capacity = signature_capacity;

	ret = statement_parts(
		statement, parts, schema, generation,
		observed_at, sequence_bytes);
	if (ret != 0) {
		goto fail;
	}
	ret = hash->digest(
		hash->context, parts,
		sizeof(parts) / sizeof(parts[0]),
		statement->transcript_digest);
	if (ret != 0) {
		goto fail;
	}
	ret = signatures->sign(
		signatures->context, authority->key_id,
		parts, sizeof(parts) / sizeof(parts[0]),
		signature_storage, signature_capacity,
		&statement->signature_length);
	if (ret != 0 || statement->signature_length == 0U ||
	    statement->signature_length > signature_capacity) {
		ret = ret != 0 ? ret : -EOVERFLOW;
		goto fail;
	}
	return 0;

fail:
	memset(signature_storage, 0, signature_capacity);
	memset(statement, 0, sizeof(*statement));
	return ret;
}

static int growth_verify(
	const struct pqcp_fleet_transparency_witness_record *record,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	const struct pqcp_fleet_transparency_consistency_proof *proof,
	const struct pqcp_fleet_transparency_hash_ops *hash)
{
	if (proof == NULL ||
	    proof->old_tree_size != record->latest_tree_size ||
	    proof->new_tree_size != checkpoint->tree_size ||
	    !bytes_equal(
		    proof->old_root, record->latest_root,
		    sizeof(proof->old_root)) ||
	    !bytes_equal(
		    proof->new_root, checkpoint->root,
		    sizeof(proof->new_root))) {
		return -EBADMSG;
	}
	return pqcp_fleet_transparency_consistency_proof_verify(
		hash, proof);
}

int pqcp_fleet_transparency_witness_observe(
	struct pqcp_fleet_transparency_witness_registry *registry,
	const struct pqcp_fleet_transparency_witness_statement *statement,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	const struct pqcp_fleet_transparency_consistency_proof *consistency,
	uint64_t now_ms,
	struct pqcp_fleet_transparency_evidence *evidence)
{
	struct pqcp_fleet_transparency_witness_record *record;
	uint8_t *signature;
	int index;
	int ret;

	if (!registry_valid(registry) || statement == NULL ||
	    checkpoint == NULL ||
	    statement->observed_at_ms > now_ms ||
	    registry->generation == UINT64_MAX) {
		return -EINVAL;
	}
	if (evidence != NULL) {
		memset(evidence, 0, sizeof(*evidence));
	}
	ret = pqcp_fleet_transparency_checkpoint_verify(
		checkpoint, &registry->hash,
		&registry->signatures);
	if (ret != 0) {
		return ret;
	}
	if (!bytes_equal(
		    checkpoint->log_id, registry->log_id,
		    sizeof(registry->log_id)) ||
	    !bytes_equal(
		    checkpoint->signer_key_id,
		    registry->trusted_log_key_id,
		    sizeof(registry->trusted_log_key_id)) ||
	    !bytes_equal(
		    statement->checkpoint_digest,
		    checkpoint->transcript_digest,
		    sizeof(statement->checkpoint_digest))) {
		return -EKEYREJECTED;
	}
	index = record_index(registry, statement->witness_id);
	if (index < 0) {
		return -ENOENT;
	}
	record = &registry->records[index];
	if (record->authority.state !=
		    PQCP_FLEET_TRANSPARENCY_WITNESS_ACTIVE ||
	    statement->authority_generation !=
		    record->authority.generation) {
		return -EKEYREVOKED;
	}
	if (statement->observed_at_ms <
		    record->authority.not_before_ms ||
	    statement->observed_at_ms >=
		    record->authority.expires_at_ms) {
		return -EKEYEXPIRED;
	}
	ret = statement_verify(
		statement, &record->authority,
		&registry->hash, &registry->signatures);
	if (ret != 0) {
		return ret;
	}
	if (statement->signature_length >
	    registry->signature_stride) {
		return -ENOSPC;
	}

	if (record->has_observation) {
		if (statement->sequence <=
		    record->latest_sequence) {
			(void)evidence_set(
				evidence,
				PQCP_FLEET_TRANSPARENCY_EVIDENCE_REPLAY,
				record, statement, checkpoint,
				now_ms, &registry->hash);
			return -EALREADY;
		}
		if (checkpoint->tree_size <
		    record->latest_tree_size) {
			(void)evidence_set(
				evidence,
				PQCP_FLEET_TRANSPARENCY_EVIDENCE_ROLLBACK,
				record, statement, checkpoint,
				now_ms, &registry->hash);
			return -ESTALE;
		}
		if (checkpoint->tree_size ==
		    record->latest_tree_size) {
			if (!bytes_equal(
				    checkpoint->root,
				    record->latest_root,
				    sizeof(checkpoint->root))) {
				(void)evidence_set(
					evidence,
					PQCP_FLEET_TRANSPARENCY_EVIDENCE_EQUIVOCATION,
					record, statement, checkpoint,
					now_ms, &registry->hash);
				return -EKEYREJECTED;
			}
		} else {
			ret = growth_verify(
				record, checkpoint, consistency,
				&registry->hash);
			if (ret != 0) {
				(void)evidence_set(
					evidence,
					PQCP_FLEET_TRANSPARENCY_EVIDENCE_INCONSISTENT_GROWTH,
					record, statement, checkpoint,
					now_ms, &registry->hash);
				return ret;
			}
		}
	}

	signature = record_signature(registry, (size_t)index);
	memset(signature, 0, registry->signature_stride);
	memcpy(signature, statement->signature,
	       statement->signature_length);
	record->latest_tree_size = checkpoint->tree_size;
	record->latest_observed_at_ms =
		statement->observed_at_ms;
	record->latest_sequence = statement->sequence;
	memcpy(record->latest_root, checkpoint->root,
	       sizeof(record->latest_root));
	memcpy(record->latest_checkpoint_digest,
	       checkpoint->transcript_digest,
	       sizeof(record->latest_checkpoint_digest));
	memcpy(record->latest_statement_digest,
	       statement->transcript_digest,
	       sizeof(record->latest_statement_digest));
	record->signature_length = statement->signature_length;
	record->has_observation = true;
	++registry->generation;
	return 0;
}

int pqcp_fleet_transparency_witness_quorum_evaluate(
	const struct pqcp_fleet_transparency_witness_registry *registry,
	const struct pqcp_fleet_transparency_checkpoint *checkpoint,
	const struct pqcp_fleet_transparency_witness_policy *policy,
	uint64_t now_ms,
	struct pqcp_fleet_transparency_witness_quorum *quorum)
{
	int ret;

	if (!registry_valid(registry) || checkpoint == NULL ||
	    policy == NULL || quorum == NULL ||
	    policy->minimum_witnesses == 0U ||
	    policy->minimum_weight == 0U) {
		return -EINVAL;
	}
	ret = pqcp_fleet_transparency_checkpoint_verify(
		checkpoint, &registry->hash,
		&registry->signatures);
	if (ret != 0) {
		return ret;
	}
	if (!bytes_equal(
		    checkpoint->log_id, registry->log_id,
		    sizeof(registry->log_id)) ||
	    !bytes_equal(
		    checkpoint->signer_key_id,
		    registry->trusted_log_key_id,
		    sizeof(registry->trusted_log_key_id))) {
		return -EKEYREJECTED;
	}

	memset(quorum, 0, sizeof(*quorum));
	memcpy(quorum->checkpoint_digest,
	       checkpoint->transcript_digest,
	       sizeof(quorum->checkpoint_digest));
	for (size_t index = 0U;
	     index < registry->capacity;
	     ++index) {
		const struct pqcp_fleet_transparency_witness_record *record =
			&registry->records[index];

		if (record->authority.state !=
			    PQCP_FLEET_TRANSPARENCY_WITNESS_ACTIVE ||
		    !record->has_observation ||
		    !bytes_equal(
			    record->latest_checkpoint_digest,
			    checkpoint->transcript_digest,
			    sizeof(record->latest_checkpoint_digest)) ||
		    record->latest_observed_at_ms > now_ms ||
		    now_ms < record->authority.not_before_ms ||
		    now_ms >= record->authority.expires_at_ms) {
			continue;
		}
		if (policy->maximum_observation_age_ms != 0U &&
		    now_ms - record->latest_observed_at_ms >
			    policy->maximum_observation_age_ms) {
			continue;
		}
		if (quorum->witness_count != UINT32_MAX) {
			++quorum->witness_count;
		}
		if (UINT32_MAX - quorum->total_weight <
		    record->authority.weight) {
			quorum->total_weight = UINT32_MAX;
		} else {
			quorum->total_weight +=
				record->authority.weight;
		}
		quorum->observed_roles |=
			record->authority.roles;
	}
	quorum->count_met =
		quorum->witness_count >= policy->minimum_witnesses;
	quorum->weight_met =
		quorum->total_weight >= policy->minimum_weight;
	quorum->roles_met =
		(quorum->observed_roles & policy->required_roles) ==
		policy->required_roles;
	quorum->reached = quorum->count_met &&
		quorum->weight_met && quorum->roles_met;
	return 0;
}

int pqcp_fleet_transparency_witness_registry_verify(
	const struct pqcp_fleet_transparency_witness_registry *registry)
{
	if (!registry_valid(registry) ||
	    registry->generation == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < registry->capacity;
	     ++index) {
		const struct pqcp_fleet_transparency_witness_record *record =
			&registry->records[index];

		if (record->authority.state ==
		    PQCP_FLEET_TRANSPARENCY_WITNESS_EMPTY) {
			if (record->has_observation ||
			    record->signature_length != 0U) {
				return -EILSEQ;
			}
			continue;
		}
		if (!authority_valid(&record->authority) ||
		    record->signature_length >
			    registry->signature_stride ||
		    (record->has_observation &&
		     (record->latest_sequence == 0U ||
		      record->signature_length == 0U))) {
			return -EILSEQ;
		}
		for (size_t other = index + 1U;
		     other < registry->capacity;
		     ++other) {
			if (registry->records[other].authority.state !=
				    PQCP_FLEET_TRANSPARENCY_WITNESS_EMPTY &&
			    bytes_equal(
				    record->authority.witness_id,
				    registry->records[other].
					    authority.witness_id,
				    sizeof(record->authority.witness_id))) {
				return -EILSEQ;
			}
		}
	}
	return 0;
}
