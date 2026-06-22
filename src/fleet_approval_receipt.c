/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deterministic approval certificates and fail-closed replay consumption.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_approval.h>

static const uint8_t vote_context[] =
	"PQCP-FLEET-APPROVAL-VOTE-V1";
static const uint8_t commitment_context[] =
	"PQCP-FLEET-APPROVAL-SIGNER-COMMITMENT-V1";
static const uint8_t certificate_context[] =
	"PQCP-FLEET-APPROVAL-CERTIFICATE-V1";

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

static int bytes_compare(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	for (size_t index = 0U; index < length; ++index) {
		if (left[index] < right[index]) {
			return -1;
		}
		if (left[index] > right[index]) {
			return 1;
		}
	}
	return 0;
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

static bool set_valid(
	const struct pqcp_fleet_approval_authority_set *set)
{
	return set != NULL && set->initialized &&
	       set->schema_version ==
		       PQCP_FLEET_APPROVAL_SCHEMA_VERSION &&
	       set->generation != 0U &&
	       set->authorities != NULL && set->capacity != 0U &&
	       set->hash.digest != NULL &&
	       set->signatures.verify != NULL;
}

static bool session_valid(
	const struct pqcp_fleet_approval_session *session)
{
	return session != NULL &&
	       session->schema_version ==
		       PQCP_FLEET_APPROVAL_SCHEMA_VERSION &&
	       session->policy_generation != 0U &&
	       bytes_nonzero(
		       session->session_id,
		       sizeof(session->session_id)) &&
	       session->votes != NULL &&
	       session->vote_count <= session->vote_capacity &&
	       session->signature_arena != NULL &&
	       session->signature_stride != 0U;
}

static int authority_index(
	const struct pqcp_fleet_approval_authority_set *set,
	const uint8_t authority_id[PQCP_FLEET_APPROVAL_ID_BYTES])
{
	for (size_t index = 0U; index < set->capacity; ++index) {
		if (set->authorities[index].state !=
			    PQCP_FLEET_APPROVAL_AUTHORITY_EMPTY &&
		    bytes_equal(
			    set->authorities[index].authority_id,
			    authority_id,
			    PQCP_FLEET_APPROVAL_ID_BYTES)) {
			return (int)index;
		}
	}
	return -1;
}

static int vote_record_index_after(
	const struct pqcp_fleet_approval_session *session,
	const uint8_t previous[PQCP_FLEET_APPROVAL_ID_BYTES],
	bool have_previous)
{
	int selected = -1;

	for (size_t index = 0U;
	     index < session->vote_count;
	     ++index) {
		const struct pqcp_fleet_approval_vote_record *record =
			&session->votes[index];

		if (!record->occupied ||
		    record->decision !=
			    PQCP_FLEET_APPROVAL_DECISION_APPROVE ||
		    (have_previous &&
		     bytes_compare(
			     record->authority_id, previous,
			     PQCP_FLEET_APPROVAL_ID_BYTES) <= 0)) {
			continue;
		}
		if (selected < 0 ||
		    bytes_compare(
			    record->authority_id,
			    session->votes[selected].authority_id,
			    PQCP_FLEET_APPROVAL_ID_BYTES) < 0) {
			selected = (int)index;
		}
	}
	return selected;
}

static int digest_signature(
	const struct pqcp_fleet_approval_authority_set *set,
	const uint8_t *signature,
	size_t signature_length,
	uint8_t output[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES])
{
	const struct pqcp_fleet_transparency_part part = {
		.data = signature,
		.length = signature_length,
	};

	return set->hash.digest(
		set->hash.context, &part, 1U, output);
}

static int signer_commitment(
	const struct pqcp_fleet_approval_authority_set *set,
	struct pqcp_fleet_approval_certificate_vote *vote)
{
	struct pqcp_fleet_transparency_part parts[5];
	uint8_t generation[4];

	write_be32(generation, vote->authority_generation);
	parts[0] = (struct pqcp_fleet_transparency_part) {
		.data = commitment_context,
		.length = sizeof(commitment_context) - 1U,
	};
	parts[1] = (struct pqcp_fleet_transparency_part) {
		.data = vote->authority_id,
		.length = sizeof(vote->authority_id),
	};
	parts[2] = (struct pqcp_fleet_transparency_part) {
		.data = generation, .length = sizeof(generation),
	};
	parts[3] = (struct pqcp_fleet_transparency_part) {
		.data = vote->vote_digest,
		.length = sizeof(vote->vote_digest),
	};
	parts[4] = (struct pqcp_fleet_transparency_part) {
		.data = vote->signature_digest,
		.length = sizeof(vote->signature_digest),
	};
	return set->hash.digest(
		set->hash.context, parts,
		sizeof(parts) / sizeof(parts[0]),
		vote->signer_commitment);
}

static int certificate_id_calculate(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_certificate *certificate,
	uint8_t output[PQCP_FLEET_APPROVAL_ID_BYTES])
{
	struct pqcp_fleet_transparency_part
		parts[20U + PQCP_FLEET_APPROVAL_MAX_CERTIFICATE_VOTES];
	uint8_t schema[4];
	uint8_t policy_generation[4];
	uint8_t action[4];
	uint8_t approval_count[4];
	uint8_t approval_weight[4];
	uint8_t approval_roles[4];
	uint8_t authority_generation[8];
	uint8_t policy_epoch[8];
	uint8_t revocation_epoch[8];
	uint8_t issued_at[8];
	uint8_t expires_at[8];
	uint8_t checkpoint_size[8];
	size_t part_count = 20U;

	if (certificate->vote_count >
	    PQCP_FLEET_APPROVAL_MAX_CERTIFICATE_VOTES) {
		return -E2BIG;
	}
	write_be32(schema, certificate->schema_version);
	write_be32(
		policy_generation,
		certificate->policy_generation);
	write_be32(action, (uint32_t)certificate->action);
	write_be32(approval_count, certificate->approval_count);
	write_be32(approval_weight, certificate->approval_weight);
	write_be32(approval_roles, certificate->approval_roles);
	write_be64(
		authority_generation,
		certificate->authority_set_generation);
	write_be64(policy_epoch, certificate->policy_epoch);
	write_be64(revocation_epoch, certificate->revocation_epoch);
	write_be64(issued_at, certificate->issued_at_ms);
	write_be64(expires_at, certificate->expires_at_ms);
	write_be64(
		checkpoint_size,
		certificate->checkpoint_tree_size);
	parts[0] = (struct pqcp_fleet_transparency_part) {
		.data = certificate_context,
		.length = sizeof(certificate_context) - 1U,
	};
	parts[1] = (struct pqcp_fleet_transparency_part) {
		.data = schema, .length = 4U,
	};
	parts[2] = (struct pqcp_fleet_transparency_part) {
		.data = certificate->session_id,
		.length = sizeof(certificate->session_id),
	};
	parts[3] = (struct pqcp_fleet_transparency_part) {
		.data = certificate->policy_id,
		.length = sizeof(certificate->policy_id),
	};
	parts[4] = (struct pqcp_fleet_transparency_part) {
		.data = policy_generation, .length = 4U,
	};
	parts[5] = (struct pqcp_fleet_transparency_part) {
		.data = action, .length = 4U,
	};
	parts[6] = (struct pqcp_fleet_transparency_part) {
		.data = certificate->target_id,
		.length = sizeof(certificate->target_id),
	};
	parts[7] = (struct pqcp_fleet_transparency_part) {
		.data = certificate->artifact_digest,
		.length = sizeof(certificate->artifact_digest),
	};
	parts[8] = (struct pqcp_fleet_transparency_part) {
		.data = authority_generation, .length = 8U,
	};
	parts[9] = (struct pqcp_fleet_transparency_part) {
		.data = policy_epoch, .length = 8U,
	};
	parts[10] = (struct pqcp_fleet_transparency_part) {
		.data = revocation_epoch, .length = 8U,
	};
	parts[11] = (struct pqcp_fleet_transparency_part) {
		.data = issued_at, .length = 8U,
	};
	parts[12] = (struct pqcp_fleet_transparency_part) {
		.data = expires_at, .length = 8U,
	};
	parts[13] = (struct pqcp_fleet_transparency_part) {
		.data = certificate->checkpoint_log_id,
		.length = sizeof(certificate->checkpoint_log_id),
	};
	parts[14] = (struct pqcp_fleet_transparency_part) {
		.data = checkpoint_size, .length = 8U,
	};
	parts[15] = (struct pqcp_fleet_transparency_part) {
		.data = certificate->checkpoint_root,
		.length = sizeof(certificate->checkpoint_root),
	};
	parts[16] = (struct pqcp_fleet_transparency_part) {
		.data = certificate->checkpoint_digest,
		.length = sizeof(certificate->checkpoint_digest),
	};
	parts[17] = (struct pqcp_fleet_transparency_part) {
		.data = approval_count, .length = 4U,
	};
	parts[18] = (struct pqcp_fleet_transparency_part) {
		.data = approval_weight, .length = 4U,
	};
	parts[19] = (struct pqcp_fleet_transparency_part) {
		.data = approval_roles, .length = 4U,
	};
	for (size_t index = 0U;
	     index < certificate->vote_count;
	     ++index) {
		parts[part_count++] =
			(struct pqcp_fleet_transparency_part) {
				.data = certificate->votes[index].
					signer_commitment,
				.length =
					PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES,
			};
	}
	return set->hash.digest(
		set->hash.context, parts, part_count, output);
}

static int vote_parts(
	const struct pqcp_fleet_approval_certificate_vote *certificate_vote,
	const uint8_t session_id[PQCP_FLEET_APPROVAL_ID_BYTES],
	struct pqcp_fleet_transparency_part parts[8],
	uint8_t schema[4],
	uint8_t generation[4],
	uint8_t decision[4],
	uint8_t issued_at[8],
	uint8_t sequence[8])
{
	write_be32(schema, PQCP_FLEET_APPROVAL_SCHEMA_VERSION);
	write_be32(generation, certificate_vote->authority_generation);
	write_be32(
		decision, PQCP_FLEET_APPROVAL_DECISION_APPROVE);
	write_be64(issued_at, certificate_vote->issued_at_ms);
	write_be64(sequence, certificate_vote->sequence);
	parts[0] = (struct pqcp_fleet_transparency_part) {
		.data = vote_context,
		.length = sizeof(vote_context) - 1U,
	};
	parts[1] = (struct pqcp_fleet_transparency_part) {
		.data = schema, .length = 4U,
	};
	parts[2] = (struct pqcp_fleet_transparency_part) {
		.data = session_id,
		.length = PQCP_FLEET_APPROVAL_ID_BYTES,
	};
	parts[3] = (struct pqcp_fleet_transparency_part) {
		.data = certificate_vote->authority_id,
		.length = sizeof(certificate_vote->authority_id),
	};
	parts[4] = (struct pqcp_fleet_transparency_part) {
		.data = generation, .length = 4U,
	};
	parts[5] = (struct pqcp_fleet_transparency_part) {
		.data = decision, .length = 4U,
	};
	parts[6] = (struct pqcp_fleet_transparency_part) {
		.data = issued_at, .length = 8U,
	};
	parts[7] = (struct pqcp_fleet_transparency_part) {
		.data = sequence, .length = 8U,
	};
	return 0;
}

int pqcp_fleet_approval_certificate_build(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	struct pqcp_fleet_approval_session *session,
	uint64_t now_ms,
	struct pqcp_fleet_approval_certificate_vote *certificate_votes,
	size_t vote_capacity,
	uint8_t *signature_arena,
	size_t signature_stride,
	struct pqcp_fleet_approval_certificate *certificate)
{
	uint8_t previous[PQCP_FLEET_APPROVAL_ID_BYTES] = { 0 };
	bool have_previous = false;
	int ret;

	if (!set_valid(set) ||
	    pqcp_fleet_approval_policy_validate(policy) != 0 ||
	    !session_valid(session) || certificate_votes == NULL ||
	    vote_capacity < session->approved_count ||
	    session->approved_count >
		    PQCP_FLEET_APPROVAL_MAX_CERTIFICATE_VOTES ||
	    signature_arena == NULL || signature_stride == 0U ||
	    vote_capacity > SIZE_MAX / signature_stride ||
	    certificate == NULL) {
		return -EINVAL;
	}
	ret = pqcp_fleet_approval_session_refresh(
		set, policy, now_ms, session);
	if (ret != 0) {
		return ret;
	}
	if (session->state !=
	    PQCP_FLEET_APPROVAL_SESSION_QUORUM) {
		return -EACCES;
	}

	memset(certificate, 0, sizeof(*certificate));
	memset(certificate_votes, 0,
	       vote_capacity * sizeof(*certificate_votes));
	memset(signature_arena, 0,
	       vote_capacity * signature_stride);
	certificate->schema_version =
		PQCP_FLEET_APPROVAL_SCHEMA_VERSION;
	certificate->policy_generation =
		session->policy_generation;
	certificate->authority_set_generation =
		session->authority_set_generation;
	certificate->policy_epoch = session->policy_epoch;
	certificate->revocation_epoch =
		session->revocation_epoch;
	certificate->issued_at_ms = now_ms;
	certificate->expires_at_ms = session->deadline_ms;
	certificate->checkpoint_tree_size =
		session->checkpoint_tree_size;
	certificate->action = session->action;
	memcpy(certificate->session_id, session->session_id,
	       sizeof(certificate->session_id));
	memcpy(certificate->policy_id, session->policy_id,
	       sizeof(certificate->policy_id));
	memcpy(certificate->target_id, session->target_id,
	       sizeof(certificate->target_id));
	memcpy(certificate->artifact_digest,
	       session->artifact_digest,
	       sizeof(certificate->artifact_digest));
	memcpy(certificate->checkpoint_log_id,
	       session->checkpoint_log_id,
	       sizeof(certificate->checkpoint_log_id));
	memcpy(certificate->checkpoint_root,
	       session->checkpoint_root,
	       sizeof(certificate->checkpoint_root));
	memcpy(certificate->checkpoint_digest,
	       session->checkpoint_digest,
	       sizeof(certificate->checkpoint_digest));
	certificate->votes = certificate_votes;
	certificate->vote_capacity = vote_capacity;
	certificate->signature_arena = signature_arena;
	certificate->signature_stride = signature_stride;

	for (size_t output_index = 0U;
	     output_index < session->approved_count;
	     ++output_index) {
		struct pqcp_fleet_approval_certificate_vote *output =
			&certificate_votes[output_index];
		const struct pqcp_fleet_approval_vote_record *source;
		const struct pqcp_fleet_approval_authority *authority;
		uint8_t *source_signature;
		uint8_t *output_signature;
		int source_index;
		int authority_slot;

		source_index = vote_record_index_after(
			session, previous, have_previous);
		if (source_index < 0) {
			ret = -EILSEQ;
			goto fail;
		}
		source = &session->votes[source_index];
		authority_slot = authority_index(
			set, source->authority_id);
		if (authority_slot < 0) {
			ret = -ENOENT;
			goto fail;
		}
		authority = &set->authorities[authority_slot];
		if (source->signature_length > signature_stride ||
		    authority->state !=
			    PQCP_FLEET_APPROVAL_AUTHORITY_ACTIVE ||
		    authority->generation !=
			    source->authority_generation ||
		    now_ms >= authority->expires_at_ms) {
			ret = -EKEYREVOKED;
			goto fail;
		}
		output->authority_generation =
			source->authority_generation;
		output->issued_at_ms = source->issued_at_ms;
		output->sequence = source->sequence;
		memcpy(output->authority_id, source->authority_id,
		       sizeof(output->authority_id));
		memcpy(output->vote_digest,
		       source->transcript_digest,
		       sizeof(output->vote_digest));
		source_signature = session->signature_arena +
			(size_t)source_index *
				session->signature_stride;
		output_signature = signature_arena +
			output_index * signature_stride;
		memcpy(output_signature, source_signature,
		       source->signature_length);
		output->signature = output_signature;
		output->signature_capacity = signature_stride;
		output->signature_length =
			source->signature_length;
		ret = digest_signature(
			set, output->signature,
			output->signature_length,
			output->signature_digest);
		if (ret != 0) {
			goto fail;
		}
		ret = signer_commitment(set, output);
		if (ret != 0) {
			goto fail;
		}
		++certificate->approval_count;
		if (UINT32_MAX - certificate->approval_weight <
		    authority->weight) {
			certificate->approval_weight = UINT32_MAX;
		} else {
			certificate->approval_weight +=
				authority->weight;
		}
		certificate->approval_roles |= authority->roles;
		memcpy(previous, source->authority_id,
		       sizeof(previous));
		have_previous = true;
	}
	certificate->vote_count = certificate->approval_count;
	ret = certificate_id_calculate(
		set, certificate, certificate->certificate_id);
	if (ret != 0 ||
	    !bytes_nonzero(
		    certificate->certificate_id,
		    sizeof(certificate->certificate_id))) {
		ret = ret != 0 ? ret : -EKEYREJECTED;
		goto fail;
	}
	session->state =
		PQCP_FLEET_APPROVAL_SESSION_CERTIFIED;
	return 0;

fail:
	memset(certificate_votes, 0,
	       vote_capacity * sizeof(*certificate_votes));
	memset(signature_arena, 0,
	       vote_capacity * signature_stride);
	memset(certificate, 0, sizeof(*certificate));
	return ret;
}

static int certificate_vote_verify(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_certificate *certificate,
	const struct pqcp_fleet_approval_certificate_vote *vote,
	const struct pqcp_fleet_approval_authority *authority)
{
	struct pqcp_fleet_transparency_part parts[8];
	uint8_t vote_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t signature_digest[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	struct pqcp_fleet_approval_certificate_vote prepared;
	uint8_t schema[4];
	uint8_t generation[4];
	uint8_t decision[4];
	uint8_t issued_at[8];
	uint8_t sequence[8];
	int ret;

	if (vote->signature == NULL ||
	    vote->signature_length == 0U ||
	    vote->signature_length > vote->signature_capacity ||
	    vote->authority_generation != authority->generation ||
	    vote->issued_at_ms < authority->not_before_ms ||
	    vote->issued_at_ms >= authority->expires_at_ms ||
	    (authority->action_mask &
	     PQCP_FLEET_APPROVAL_ACTION_BIT(certificate->action)) == 0U) {
		return -EKEYREVOKED;
	}
	(void)vote_parts(
		vote, certificate->session_id, parts,
		schema, generation, decision, issued_at, sequence);
	ret = set->hash.digest(
		set->hash.context, parts,
		sizeof(parts) / sizeof(parts[0]), vote_digest);
	if (ret != 0) {
		return ret;
	}
	if (!bytes_equal(
		    vote_digest, vote->vote_digest,
		    sizeof(vote_digest))) {
		return -EKEYREJECTED;
	}
	ret = set->signatures.verify(
		set->signatures.context, authority->key_id,
		parts, sizeof(parts) / sizeof(parts[0]),
		vote->signature, vote->signature_length);
	if (ret != 0) {
		return ret;
	}
	ret = digest_signature(
		set, vote->signature, vote->signature_length,
		signature_digest);
	if (ret != 0 ||
	    !bytes_equal(
		    signature_digest, vote->signature_digest,
		    sizeof(signature_digest))) {
		return ret != 0 ? ret : -EKEYREJECTED;
	}
	prepared = *vote;
	ret = signer_commitment(set, &prepared);
	if (ret != 0 ||
	    !bytes_equal(
		    prepared.signer_commitment,
		    vote->signer_commitment,
		    sizeof(prepared.signer_commitment))) {
		return ret != 0 ? ret : -EKEYREJECTED;
	}
	return 0;
}

int pqcp_fleet_approval_certificate_verify(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	const struct pqcp_fleet_approval_session *session,
	const struct pqcp_fleet_approval_certificate *certificate,
	uint64_t now_ms)
{
	uint8_t calculated_id[PQCP_FLEET_APPROVAL_ID_BYTES];
	uint32_t count = 0U;
	uint32_t weight = 0U;
	uint32_t roles = 0U;
	int ret;

	if (!set_valid(set) ||
	    pqcp_fleet_approval_policy_validate(policy) != 0 ||
	    !session_valid(session) || certificate == NULL ||
	    certificate->schema_version !=
		    PQCP_FLEET_APPROVAL_SCHEMA_VERSION ||
	    certificate->votes == NULL ||
	    certificate->vote_count == 0U ||
	    certificate->vote_count >
		    certificate->vote_capacity ||
	    certificate->vote_count >
		    PQCP_FLEET_APPROVAL_MAX_CERTIFICATE_VOTES ||
	    certificate->signature_arena == NULL ||
	    certificate->signature_stride == 0U ||
	    certificate->issued_at_ms > now_ms ||
	    now_ms > certificate->expires_at_ms ||
	    certificate->policy_generation != policy->generation ||
	    certificate->policy_generation !=
		    session->policy_generation ||
	    certificate->authority_set_generation != set->generation ||
	    certificate->authority_set_generation !=
		    session->authority_set_generation ||
	    certificate->policy_epoch != set->policy_epoch ||
	    certificate->revocation_epoch !=
		    set->revocation_epoch ||
	    certificate->policy_epoch != policy->policy_epoch ||
	    certificate->revocation_epoch !=
		    policy->revocation_epoch ||
	    certificate->action != session->action ||
	    !bytes_equal(
		    certificate->session_id, session->session_id,
		    sizeof(certificate->session_id)) ||
	    !bytes_equal(
		    certificate->policy_id, session->policy_id,
		    sizeof(certificate->policy_id)) ||
	    !bytes_equal(
		    certificate->target_id, session->target_id,
		    sizeof(certificate->target_id)) ||
	    !bytes_equal(
		    certificate->artifact_digest,
		    session->artifact_digest,
		    sizeof(certificate->artifact_digest)) ||
	    certificate->checkpoint_tree_size !=
		    session->checkpoint_tree_size ||
	    (session->state !=
		     PQCP_FLEET_APPROVAL_SESSION_CERTIFIED &&
	     session->state !=
		     PQCP_FLEET_APPROVAL_SESSION_CONSUMED) ||
	    !bytes_equal(
		    certificate->checkpoint_log_id,
		    session->checkpoint_log_id,
		    sizeof(certificate->checkpoint_log_id)) ||
	    !bytes_equal(
		    certificate->checkpoint_root,
		    session->checkpoint_root,
		    sizeof(certificate->checkpoint_root)) ||
	    !bytes_equal(
		    certificate->checkpoint_digest,
		    session->checkpoint_digest,
		    sizeof(certificate->checkpoint_digest))) {
		return -EINVAL;
	}

	for (size_t index = 0U;
	     index < certificate->vote_count;
	     ++index) {
		const struct pqcp_fleet_approval_certificate_vote *vote =
			&certificate->votes[index];
		const struct pqcp_fleet_approval_authority *authority;
		int authority_slot;

		if (index != 0U &&
		    bytes_compare(
			    certificate->votes[index - 1U].authority_id,
			    vote->authority_id,
			    sizeof(vote->authority_id)) >= 0) {
			return -EKEYREJECTED;
		}
		authority_slot = authority_index(
			set, vote->authority_id);
		if (authority_slot < 0) {
			return -ENOENT;
		}
		authority = &set->authorities[authority_slot];
		if (authority->state !=
		    PQCP_FLEET_APPROVAL_AUTHORITY_ACTIVE) {
			return -EKEYREVOKED;
		}
		ret = certificate_vote_verify(
			set, certificate, vote, authority);
		if (ret != 0) {
			return ret;
		}
		if (count != UINT32_MAX) {
			++count;
		}
		if (UINT32_MAX - weight < authority->weight) {
			weight = UINT32_MAX;
		} else {
			weight += authority->weight;
		}
		roles |= authority->roles;
	}
	if (count != certificate->approval_count ||
	    weight != certificate->approval_weight ||
	    roles != certificate->approval_roles ||
	    count < policy->minimum_approvals ||
	    weight < policy->minimum_weight ||
	    (roles & policy->required_roles) !=
		    policy->required_roles) {
		return -EACCES;
	}
	ret = certificate_id_calculate(
		set, certificate, calculated_id);
	if (ret != 0) {
		return ret;
	}
	return bytes_equal(
		calculated_id, certificate->certificate_id,
		sizeof(calculated_id)) ? 0 : -EKEYREJECTED;
}

int pqcp_fleet_approval_replay_guard_init(
	struct pqcp_fleet_approval_replay_guard *guard,
	struct pqcp_fleet_approval_replay_entry *entries,
	size_t capacity)
{
	if (guard == NULL || entries == NULL || capacity == 0U) {
		return -EINVAL;
	}
	memset(guard, 0, sizeof(*guard));
	memset(entries, 0, capacity * sizeof(*entries));
	guard->schema_version =
		PQCP_FLEET_APPROVAL_SCHEMA_VERSION;
	guard->generation = 1U;
	guard->entries = entries;
	guard->capacity = capacity;
	guard->initialized = true;
	return 0;
}

int pqcp_fleet_approval_certificate_consume(
	struct pqcp_fleet_approval_replay_guard *guard,
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	const struct pqcp_fleet_approval_certificate *certificate,
	uint64_t now_ms,
	struct pqcp_fleet_approval_session *session)
{
	int free_slot = -1;
	int ret;

	if (guard == NULL || !guard->initialized ||
	    guard->schema_version !=
		    PQCP_FLEET_APPROVAL_SCHEMA_VERSION ||
	    guard->generation == UINT64_MAX ||
	    guard->entries == NULL || guard->capacity == 0U ||
	    session == NULL) {
		return -EINVAL;
	}
	if (session->state ==
	    PQCP_FLEET_APPROVAL_SESSION_CONSUMED) {
		return -EALREADY;
	}
	if (session->state !=
	    PQCP_FLEET_APPROVAL_SESSION_CERTIFIED) {
		return -EINVAL;
	}
	ret = pqcp_fleet_approval_certificate_verify(
		set, policy, session, certificate, now_ms);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < guard->capacity; ++index) {
		if (guard->entries[index].occupied &&
		    bytes_equal(
			    guard->entries[index].certificate_id,
			    certificate->certificate_id,
			    sizeof(certificate->certificate_id))) {
			return -EALREADY;
		}
		if (!guard->entries[index].occupied &&
		    free_slot < 0) {
			free_slot = (int)index;
		}
	}
	if (free_slot < 0) {
		return -ENOSPC;
	}
	guard->entries[free_slot].occupied = true;
	guard->entries[free_slot].consumed_at_ms = now_ms;
	memcpy(guard->entries[free_slot].certificate_id,
	       certificate->certificate_id,
	       sizeof(certificate->certificate_id));
	++guard->generation;
	session->state =
		PQCP_FLEET_APPROVAL_SESSION_CONSUMED;
	return 0;
}
