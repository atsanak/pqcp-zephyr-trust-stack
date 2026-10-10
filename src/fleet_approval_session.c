/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Context-bound multi-party approval sessions and signed votes.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/errno.h>
#include <pqcp_zephyr/fleet_approval.h>

static const uint8_t session_context[] =
	"PQCP-FLEET-APPROVAL-SESSION-V1";
static const uint8_t vote_context[] =
	"PQCP-FLEET-APPROVAL-VOTE-V1";

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

static bool set_valid(
	const struct pqcp_fleet_approval_authority_set *set)
{
	return set != NULL && set->initialized &&
	       set->schema_version ==
		       PQCP_FLEET_APPROVAL_SCHEMA_VERSION &&
	       set->generation != 0U &&
	       set->policy_epoch != 0U &&
	       set->revocation_epoch != 0U &&
	       set->authorities != NULL && set->capacity != 0U &&
	       set->hash.digest != NULL &&
	       set->signatures.verify != NULL;
}

static bool action_valid(enum pqcp_fleet_approval_action action)
{
	return action > PQCP_FLEET_APPROVAL_ACTION_NONE &&
	       action < PQCP_FLEET_APPROVAL_ACTION_COUNT;
}

static bool authority_shape_valid(
	const struct pqcp_fleet_approval_authority *authority)
{
	return authority != NULL &&
	       authority->schema_version ==
		       PQCP_FLEET_APPROVAL_SCHEMA_VERSION &&
	       authority->generation != 0U &&
	       authority->roles != 0U &&
	       authority->weight != 0U &&
	       authority->action_mask != 0U &&
	       authority->expires_at_ms > authority->not_before_ms &&
	       bytes_nonzero(
		       authority->authority_id,
		       sizeof(authority->authority_id)) &&
	       bytes_nonzero(
		       authority->key_id,
		       sizeof(authority->key_id));
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

static int session_parts(
	const struct pqcp_fleet_approval_session *session,
	struct pqcp_fleet_transparency_part parts[18],
	uint8_t schema[4],
	uint8_t policy_generation[4],
	uint8_t action[4],
	uint8_t authority_generation[8],
	uint8_t policy_epoch[8],
	uint8_t revocation_epoch[8],
	uint8_t created_at[8],
	uint8_t deadline[8],
	uint8_t checkpoint_tree_size[8],
	uint8_t checkpoint_bound[1])
{
	write_be32(schema, session->schema_version);
	write_be32(policy_generation, session->policy_generation);
	write_be32(action, (uint32_t)session->action);
	write_be64(
		authority_generation,
		session->authority_set_generation);
	write_be64(policy_epoch, session->policy_epoch);
	write_be64(revocation_epoch, session->revocation_epoch);
	write_be64(created_at, session->created_at_ms);
	write_be64(deadline, session->deadline_ms);
	write_be64(
		checkpoint_tree_size,
		session->checkpoint_tree_size);
	checkpoint_bound[0] = session->checkpoint_bound ? 1U : 0U;
	parts[0] = (struct pqcp_fleet_transparency_part) {
		.data = session_context,
		.length = sizeof(session_context) - 1U,
	};
	parts[1] = (struct pqcp_fleet_transparency_part) {
		.data = schema, .length = 4U,
	};
	parts[2] = (struct pqcp_fleet_transparency_part) {
		.data = session->policy_id,
		.length = sizeof(session->policy_id),
	};
	parts[3] = (struct pqcp_fleet_transparency_part) {
		.data = policy_generation, .length = 4U,
	};
	parts[4] = (struct pqcp_fleet_transparency_part) {
		.data = action, .length = 4U,
	};
	parts[5] = (struct pqcp_fleet_transparency_part) {
		.data = session->target_id,
		.length = sizeof(session->target_id),
	};
	parts[6] = (struct pqcp_fleet_transparency_part) {
		.data = session->artifact_digest,
		.length = sizeof(session->artifact_digest),
	};
	parts[7] = (struct pqcp_fleet_transparency_part) {
		.data = session->nonce,
		.length = sizeof(session->nonce),
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
		.data = created_at, .length = 8U,
	};
	parts[12] = (struct pqcp_fleet_transparency_part) {
		.data = deadline, .length = 8U,
	};
	parts[13] = (struct pqcp_fleet_transparency_part) {
		.data = checkpoint_bound, .length = 1U,
	};
	parts[14] = (struct pqcp_fleet_transparency_part) {
		.data = session->checkpoint_log_id,
		.length = sizeof(session->checkpoint_log_id),
	};
	parts[15] = (struct pqcp_fleet_transparency_part) {
		.data = checkpoint_tree_size, .length = 8U,
	};
	parts[16] = (struct pqcp_fleet_transparency_part) {
		.data = session->checkpoint_root,
		.length = sizeof(session->checkpoint_root),
	};
	parts[17] = (struct pqcp_fleet_transparency_part) {
		.data = session->checkpoint_digest,
		.length = sizeof(session->checkpoint_digest),
	};
	return 0;
}

static int session_id_calculate(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_session *session,
	uint8_t output[PQCP_FLEET_APPROVAL_ID_BYTES])
{
	struct pqcp_fleet_transparency_part parts[18];
	uint8_t schema[4];
	uint8_t policy_generation[4];
	uint8_t action[4];
	uint8_t authority_generation[8];
	uint8_t policy_epoch[8];
	uint8_t revocation_epoch[8];
	uint8_t created_at[8];
	uint8_t deadline[8];
	uint8_t checkpoint_tree_size[8];
	uint8_t checkpoint_bound[1];

	(void)session_parts(
		session, parts, schema, policy_generation, action,
		authority_generation, policy_epoch,
		revocation_epoch, created_at, deadline,
		checkpoint_tree_size, checkpoint_bound);
	return set->hash.digest(
		set->hash.context, parts,
		sizeof(parts) / sizeof(parts[0]), output);
}

static bool session_shape_valid(
	const struct pqcp_fleet_approval_session *session)
{
	return session != NULL &&
	       session->schema_version ==
		       PQCP_FLEET_APPROVAL_SCHEMA_VERSION &&
	       session->policy_generation != 0U &&
	       action_valid(session->action) &&
	       session->authority_set_generation != 0U &&
	       session->policy_epoch != 0U &&
	       session->revocation_epoch != 0U &&
	       session->deadline_ms > session->created_at_ms &&
	       bytes_nonzero(
		       session->session_id,
		       sizeof(session->session_id)) &&
	       bytes_nonzero(
		       session->policy_id,
		       sizeof(session->policy_id)) &&
	       bytes_nonzero(
		       session->target_id,
		       sizeof(session->target_id)) &&
	       bytes_nonzero(
		       session->artifact_digest,
		       sizeof(session->artifact_digest)) &&
	       bytes_nonzero(
		       session->nonce,
		       sizeof(session->nonce)) &&
	       session->votes != NULL &&
	       session->vote_capacity != 0U &&
	       session->signature_arena != NULL &&
	       session->signature_stride != 0U &&
	       session->vote_count <= session->vote_capacity;
}

static bool policy_matches_session(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	const struct pqcp_fleet_approval_session *session)
{
	return set->generation == session->authority_set_generation &&
	       policy->generation == session->policy_generation &&
	       set->policy_epoch == session->policy_epoch &&
	       set->revocation_epoch == session->revocation_epoch &&
	       policy->policy_epoch == session->policy_epoch &&
	       policy->revocation_epoch == session->revocation_epoch &&
	       bytes_equal(
		       policy->policy_id, session->policy_id,
		       sizeof(policy->policy_id)) &&
	       (policy->action_mask &
		PQCP_FLEET_APPROVAL_ACTION_BIT(session->action)) != 0U;
}

int pqcp_fleet_approval_session_open(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	const struct pqcp_fleet_approval_session_request *request,
	struct pqcp_fleet_approval_vote_record *vote_records,
	size_t vote_capacity,
	uint8_t *signature_arena,
	size_t signature_stride,
	struct pqcp_fleet_approval_session *session)
{
	int ret;

	if (!set_valid(set) ||
	    pqcp_fleet_approval_policy_validate(policy) != 0 ||
	    request == NULL || !action_valid(request->action) ||
	    request->deadline_ms <= request->created_at_ms ||
	    request->deadline_ms - request->created_at_ms >
		    policy->maximum_session_lifetime_ms ||
	    request->policy_epoch != set->policy_epoch ||
	    request->revocation_epoch != set->revocation_epoch ||
	    policy->policy_epoch != set->policy_epoch ||
	    policy->revocation_epoch != set->revocation_epoch ||
	    (policy->action_mask &
	     PQCP_FLEET_APPROVAL_ACTION_BIT(request->action)) == 0U ||
	    !bytes_nonzero(
		    request->target_id,
		    sizeof(request->target_id)) ||
	    !bytes_nonzero(
		    request->artifact_digest,
		    sizeof(request->artifact_digest)) ||
	    !bytes_nonzero(
		    request->nonce,
		    sizeof(request->nonce)) ||
	    vote_records == NULL || vote_capacity == 0U ||
	    vote_capacity < policy->minimum_approvals ||
	    signature_arena == NULL ||
	    signature_stride == 0U ||
	    vote_capacity > SIZE_MAX / signature_stride ||
	    session == NULL) {
		return -EINVAL;
	}
	if (policy->require_witnessed_checkpoint &&
	    (request->checkpoint == NULL ||
	     request->witness_quorum == NULL ||
	     !request->witness_quorum->reached ||
	     request->witness_quorum->witness_count <
		     policy->minimum_witnesses ||
	     request->witness_quorum->total_weight <
		     policy->minimum_witness_weight ||
	     (request->witness_quorum->observed_roles &
	      policy->required_witness_roles) !=
		     policy->required_witness_roles)) {
		return -EACCES;
	}
	if ((request->checkpoint == NULL) !=
	    (request->witness_quorum == NULL)) {
		return -EINVAL;
	}

	memset(session, 0, sizeof(*session));
	session->schema_version =
		PQCP_FLEET_APPROVAL_SCHEMA_VERSION;
	session->policy_generation = policy->generation;
	session->authority_set_generation = set->generation;
	session->policy_epoch = request->policy_epoch;
	session->revocation_epoch = request->revocation_epoch;
	session->created_at_ms = request->created_at_ms;
	session->deadline_ms = request->deadline_ms;
	session->action = request->action;
	session->state = PQCP_FLEET_APPROVAL_SESSION_OPEN;
	memcpy(session->policy_id, policy->policy_id,
	       sizeof(session->policy_id));
	memcpy(session->target_id, request->target_id,
	       sizeof(session->target_id));
	memcpy(session->artifact_digest,
	       request->artifact_digest,
	       sizeof(session->artifact_digest));
	memcpy(session->nonce, request->nonce,
	       sizeof(session->nonce));
	session->votes = vote_records;
	session->vote_capacity = vote_capacity;
	session->signature_arena = signature_arena;
	session->signature_stride = signature_stride;
	memset(vote_records, 0,
	       vote_capacity * sizeof(*vote_records));
	memset(signature_arena, 0,
	       vote_capacity * signature_stride);

	if (request->checkpoint != NULL) {
		ret = pqcp_fleet_transparency_checkpoint_verify(
			request->checkpoint, &set->hash,
			&set->signatures);
		if (ret != 0 ||
		    !bytes_equal(
			    request->witness_quorum->
				    checkpoint_digest,
			    request->checkpoint->
				    transcript_digest,
			    sizeof(request->checkpoint->
				    transcript_digest)) ||
		    request->checkpoint->timestamp_ms >
			    request->created_at_ms) {
			memset(session, 0, sizeof(*session));
			return ret != 0 ? ret : -EKEYREJECTED;
		}
		session->checkpoint_bound = true;
		session->checkpoint_tree_size =
			request->checkpoint->tree_size;
		memcpy(session->checkpoint_log_id,
		       request->checkpoint->log_id,
		       sizeof(session->checkpoint_log_id));
		memcpy(session->checkpoint_root,
		       request->checkpoint->root,
		       sizeof(session->checkpoint_root));
		memcpy(session->checkpoint_digest,
		       request->checkpoint->transcript_digest,
		       sizeof(session->checkpoint_digest));
	}

	ret = session_id_calculate(
		set, session, session->session_id);
	if (ret != 0 ||
	    !bytes_nonzero(
		    session->session_id,
		    sizeof(session->session_id))) {
		memset(session, 0, sizeof(*session));
		return ret != 0 ? ret : -EKEYREJECTED;
	}
	return 0;
}

int pqcp_fleet_approval_session_refresh(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	uint64_t now_ms,
	struct pqcp_fleet_approval_session *session)
{
	if (!set_valid(set) ||
	    pqcp_fleet_approval_policy_validate(policy) != 0 ||
	    !session_shape_valid(session)) {
		return -EINVAL;
	}
	if (!policy_matches_session(set, policy, session)) {
		if (session->state == PQCP_FLEET_APPROVAL_SESSION_OPEN ||
		    session->state == PQCP_FLEET_APPROVAL_SESSION_QUORUM) {
			session->state =
				PQCP_FLEET_APPROVAL_SESSION_CANCELLED;
		}
		return -ESTALE;
	}
	if (session->state == PQCP_FLEET_APPROVAL_SESSION_CONSUMED ||
	    session->state == PQCP_FLEET_APPROVAL_SESSION_CERTIFIED) {
		return 0;
	}
	if (session->state == PQCP_FLEET_APPROVAL_SESSION_EXPIRED) {
		return -ETIMEDOUT;
	}
	if (session->state == PQCP_FLEET_APPROVAL_SESSION_CANCELLED) {
		return -ECANCELED;
	}
	if (session->state == PQCP_FLEET_APPROVAL_SESSION_DENIED) {
		return -EACCES;
	}
	if (now_ms < session->created_at_ms) {
		return -EAGAIN;
	}
	if (now_ms > session->deadline_ms) {
		session->state =
			PQCP_FLEET_APPROVAL_SESSION_EXPIRED;
		return -ETIMEDOUT;
	}
	if ((session->denied_roles & policy->veto_roles) != 0U) {
		session->state =
			PQCP_FLEET_APPROVAL_SESSION_DENIED;
		return -EACCES;
	}
	if (session->approved_count >=
		    policy->minimum_approvals &&
	    session->approved_weight >=
		    policy->minimum_weight &&
	    (session->approved_roles & policy->required_roles) ==
		    policy->required_roles) {
		session->state =
			PQCP_FLEET_APPROVAL_SESSION_QUORUM;
	} else {
		session->state =
			PQCP_FLEET_APPROVAL_SESSION_OPEN;
	}
	return 0;
}

int pqcp_fleet_approval_session_cancel(
	struct pqcp_fleet_approval_session *session)
{
	if (!session_shape_valid(session)) {
		return -EINVAL;
	}
	if (session->state != PQCP_FLEET_APPROVAL_SESSION_OPEN &&
	    session->state != PQCP_FLEET_APPROVAL_SESSION_QUORUM) {
		return -EALREADY;
	}
	session->state = PQCP_FLEET_APPROVAL_SESSION_CANCELLED;
	return 0;
}

static int vote_parts(
	const struct pqcp_fleet_approval_vote *vote,
	struct pqcp_fleet_transparency_part parts[8],
	uint8_t schema[4],
	uint8_t generation[4],
	uint8_t decision[4],
	uint8_t issued_at[8],
	uint8_t sequence[8])
{
	write_be32(schema, vote->schema_version);
	write_be32(generation, vote->authority_generation);
	write_be32(decision, (uint32_t)vote->decision);
	write_be64(issued_at, vote->issued_at_ms);
	write_be64(sequence, vote->sequence);
	parts[0] = (struct pqcp_fleet_transparency_part) {
		.data = vote_context,
		.length = sizeof(vote_context) - 1U,
	};
	parts[1] = (struct pqcp_fleet_transparency_part) {
		.data = schema, .length = 4U,
	};
	parts[2] = (struct pqcp_fleet_transparency_part) {
		.data = vote->session_id,
		.length = sizeof(vote->session_id),
	};
	parts[3] = (struct pqcp_fleet_transparency_part) {
		.data = vote->authority_id,
		.length = sizeof(vote->authority_id),
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

int pqcp_fleet_approval_vote_sign(
	const struct pqcp_fleet_approval_authority *authority,
	const struct pqcp_fleet_approval_session *session,
	enum pqcp_fleet_approval_decision decision,
	uint64_t issued_at_ms,
	uint64_t sequence,
	const struct pqcp_fleet_transparency_hash_ops *hash,
	const struct pqcp_fleet_transparency_signature_ops *signatures,
	uint8_t *signature_storage,
	size_t signature_capacity,
	struct pqcp_fleet_approval_vote *vote)
{
	struct pqcp_fleet_transparency_part parts[8];
	uint8_t schema[4];
	uint8_t generation[4];
	uint8_t decision_bytes[4];
	uint8_t issued_at[8];
	uint8_t sequence_bytes[8];
	int ret;

	if (!authority_shape_valid(authority) ||
	    authority->state !=
		    PQCP_FLEET_APPROVAL_AUTHORITY_ACTIVE ||
	    !session_shape_valid(session) ||
	    session->state !=
		    PQCP_FLEET_APPROVAL_SESSION_OPEN ||
	    (decision != PQCP_FLEET_APPROVAL_DECISION_APPROVE &&
	     decision != PQCP_FLEET_APPROVAL_DECISION_DENY) ||
	    issued_at_ms < session->created_at_ms ||
	    issued_at_ms > session->deadline_ms ||
	    issued_at_ms < authority->not_before_ms ||
	    issued_at_ms >= authority->expires_at_ms ||
	    (authority->action_mask &
	     PQCP_FLEET_APPROVAL_ACTION_BIT(session->action)) == 0U ||
	    sequence == 0U || hash == NULL ||
	    hash->digest == NULL || signatures == NULL ||
	    signatures->sign == NULL ||
	    signature_storage == NULL ||
	    signature_capacity == 0U || vote == NULL) {
		return -EINVAL;
	}
	memset(vote, 0, sizeof(*vote));
	vote->schema_version =
		PQCP_FLEET_APPROVAL_SCHEMA_VERSION;
	vote->authority_generation = authority->generation;
	vote->issued_at_ms = issued_at_ms;
	vote->sequence = sequence;
	vote->decision = decision;
	memcpy(vote->session_id, session->session_id,
	       sizeof(vote->session_id));
	memcpy(vote->authority_id, authority->authority_id,
	       sizeof(vote->authority_id));
	vote->signature = signature_storage;
	vote->signature_capacity = signature_capacity;
	(void)vote_parts(
		vote, parts, schema, generation,
		decision_bytes, issued_at, sequence_bytes);
	ret = hash->digest(
		hash->context, parts,
		sizeof(parts) / sizeof(parts[0]),
		vote->transcript_digest);
	if (ret != 0) {
		goto fail;
	}
	ret = signatures->sign(
		signatures->context, authority->key_id,
		parts, sizeof(parts) / sizeof(parts[0]),
		signature_storage, signature_capacity,
		&vote->signature_length);
	if (ret != 0 || vote->signature_length == 0U ||
	    vote->signature_length > signature_capacity) {
		ret = ret != 0 ? ret : -EOVERFLOW;
		goto fail;
	}
	return 0;

fail:
	memset(signature_storage, 0, signature_capacity);
	memset(vote, 0, sizeof(*vote));
	return ret;
}

static int vote_verify(
	const struct pqcp_fleet_approval_vote *vote,
	const struct pqcp_fleet_approval_authority *authority,
	const struct pqcp_fleet_approval_authority_set *set)
{
	struct pqcp_fleet_transparency_part parts[8];
	uint8_t calculated[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	uint8_t schema[4];
	uint8_t generation[4];
	uint8_t decision[4];
	uint8_t issued_at[8];
	uint8_t sequence[8];
	int ret;

	if (vote == NULL ||
	    vote->schema_version !=
		    PQCP_FLEET_APPROVAL_SCHEMA_VERSION ||
	    vote->authority_generation != authority->generation ||
	    vote->sequence == 0U ||
	    (vote->decision !=
		     PQCP_FLEET_APPROVAL_DECISION_APPROVE &&
	     vote->decision !=
		     PQCP_FLEET_APPROVAL_DECISION_DENY) ||
	    vote->signature == NULL ||
	    vote->signature_length == 0U ||
	    vote->signature_length > vote->signature_capacity ||
	    !bytes_equal(
		    vote->authority_id, authority->authority_id,
		    sizeof(vote->authority_id))) {
		return -EINVAL;
	}
	(void)vote_parts(
		vote, parts, schema, generation,
		decision, issued_at, sequence);
	ret = set->hash.digest(
		set->hash.context, parts,
		sizeof(parts) / sizeof(parts[0]), calculated);
	if (ret != 0) {
		return ret;
	}
	if (!bytes_equal(
		    calculated, vote->transcript_digest,
		    sizeof(calculated))) {
		return -EKEYREJECTED;
	}
	return set->signatures.verify(
		set->signatures.context, authority->key_id,
		parts, sizeof(parts) / sizeof(parts[0]),
		vote->signature, vote->signature_length);
}

int pqcp_fleet_approval_vote_submit(
	const struct pqcp_fleet_approval_authority_set *set,
	const struct pqcp_fleet_approval_policy *policy,
	const struct pqcp_fleet_approval_vote *vote,
	uint64_t now_ms,
	struct pqcp_fleet_approval_session *session)
{
	struct pqcp_fleet_approval_vote_record *record;
	const struct pqcp_fleet_approval_authority *authority;
	uint8_t *signature_slot;
	int index;
	int ret;

	if (!set_valid(set) ||
	    pqcp_fleet_approval_policy_validate(policy) != 0 ||
	    !session_shape_valid(session) || vote == NULL) {
		return -EINVAL;
	}
	ret = pqcp_fleet_approval_session_refresh(
		set, policy, now_ms, session);
	if (ret != 0) {
		return ret;
	}
	if (session->state != PQCP_FLEET_APPROVAL_SESSION_OPEN) {
		return -EALREADY;
	}
	if (!bytes_equal(
		    vote->session_id, session->session_id,
		    sizeof(vote->session_id)) ||
	    vote->issued_at_ms < session->created_at_ms ||
	    vote->issued_at_ms > session->deadline_ms ||
	    vote->issued_at_ms > now_ms) {
		return -EKEYREJECTED;
	}
	index = authority_index(set, vote->authority_id);
	if (index < 0) {
		return -ENOENT;
	}
	authority = &set->authorities[index];
	if (authority->state !=
		    PQCP_FLEET_APPROVAL_AUTHORITY_ACTIVE ||
	    authority->generation !=
		    vote->authority_generation) {
		return -EKEYREVOKED;
	}
	if (vote->issued_at_ms < authority->not_before_ms ||
	    vote->issued_at_ms >= authority->expires_at_ms ||
	    now_ms >= authority->expires_at_ms) {
		return -EKEYEXPIRED;
	}
	if ((authority->action_mask &
	     PQCP_FLEET_APPROVAL_ACTION_BIT(session->action)) == 0U) {
		return -EACCES;
	}
	for (size_t vote_index = 0U;
	     vote_index < session->vote_count;
	     ++vote_index) {
		if (session->votes[vote_index].occupied &&
		    bytes_equal(
			    session->votes[vote_index].authority_id,
			    vote->authority_id,
			    sizeof(vote->authority_id))) {
			return -EALREADY;
		}
	}
	if (session->vote_count >= session->vote_capacity ||
	    vote->signature_length > session->signature_stride) {
		return -ENOSPC;
	}
	ret = vote_verify(vote, authority, set);
	if (ret != 0) {
		return ret;
	}

	record = &session->votes[session->vote_count];
	memset(record, 0, sizeof(*record));
	record->authority_generation =
		vote->authority_generation;
	record->issued_at_ms = vote->issued_at_ms;
	record->sequence = vote->sequence;
	record->decision = vote->decision;
	memcpy(record->authority_id, vote->authority_id,
	       sizeof(record->authority_id));
	memcpy(record->transcript_digest,
	       vote->transcript_digest,
	       sizeof(record->transcript_digest));
	record->signature_length = vote->signature_length;
	record->occupied = true;
	signature_slot = session->signature_arena +
		session->vote_count * session->signature_stride;
	memset(signature_slot, 0, session->signature_stride);
	memcpy(signature_slot, vote->signature,
	       vote->signature_length);
	++session->vote_count;

	if (vote->decision ==
	    PQCP_FLEET_APPROVAL_DECISION_APPROVE) {
		if (session->approved_count != UINT32_MAX) {
			++session->approved_count;
		}
		if (UINT32_MAX - session->approved_weight <
		    authority->weight) {
			session->approved_weight = UINT32_MAX;
		} else {
			session->approved_weight += authority->weight;
		}
		session->approved_roles |= authority->roles;
	} else {
		session->denied_roles |= authority->roles;
	}
	return pqcp_fleet_approval_session_refresh(
		set, policy, now_ms, session);
}
