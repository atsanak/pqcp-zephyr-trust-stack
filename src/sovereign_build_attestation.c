/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Opaque-key build attestation verification and bounded storage.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_artifact_internal.h"

#define BUILD_ATTESTATION_CONTEXT "PQCP-SOVEREIGN-BUILD-V1"
#define BUILD_ATTESTATION_CONTEXT_BYTES 23U

struct attestation_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
};

static void attestation_write_bytes(
	struct attestation_writer *writer,
	const void *value,
	size_t length)
{
	if (writer == NULL || writer->error != 0) {
		return;
	}
	if ((value == NULL && length != 0U) ||
	    length > writer->capacity - writer->offset) {
		writer->error = -EOVERFLOW;
		return;
	}
	if (length != 0U) {
		memcpy(writer->buffer + writer->offset,
		       value, length);
	}
	writer->offset += length;
}

static void attestation_write_u16(
	struct attestation_writer *writer,
	uint16_t value)
{
	uint8_t encoded[2];

	pqcp_runtime_internal_write_u16(encoded, value);
	attestation_write_bytes(
		writer, encoded, sizeof(encoded));
}

static void attestation_write_u32(
	struct attestation_writer *writer,
	uint32_t value)
{
	uint8_t encoded[4];

	pqcp_runtime_internal_write_u32(encoded, value);
	attestation_write_bytes(
		writer, encoded, sizeof(encoded));
}

static void attestation_write_u64(
	struct attestation_writer *writer,
	uint64_t value)
{
	uint8_t encoded[8];

	pqcp_runtime_internal_write_u64(encoded, value);
	attestation_write_bytes(
		writer, encoded, sizeof(encoded));
}

static void attestation_write_text(
	struct attestation_writer *writer,
	const char *value,
	size_t capacity)
{
	size_t length;

	if (!pqcp_sovereign_internal_text_valid(
		    value, capacity)) {
		if (writer != NULL) {
			writer->error = -EINVAL;
		}
		return;
	}
	length = strnlen(value, capacity);
	if (length > UINT16_MAX) {
		writer->error = -EOVERFLOW;
		return;
	}
	attestation_write_u16(writer, (uint16_t)length);
	attestation_write_bytes(writer, value, length);
}

static bool attestation_text_valid(
	const struct pqcp_sovereign_build_attestation *attestation)
{
	return attestation != NULL &&
	       pqcp_sovereign_internal_text_valid(
		       attestation->artifact_id,
		       sizeof(attestation->artifact_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       attestation->builder_id,
		       sizeof(attestation->builder_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       attestation->build_environment,
		       sizeof(attestation->build_environment)) &&
	       pqcp_sovereign_internal_text_valid(
		       attestation->source_uri,
		       sizeof(attestation->source_uri));
}

static bool attestation_digest_fields_valid(
	const struct pqcp_sovereign_build_attestation *attestation,
	bool require_statement_digest,
	bool require_signature_digest)
{
	if (attestation == NULL ||
	    pqcp_sovereign_internal_all_zero(
		    attestation->source_digest,
		    sizeof(attestation->source_digest)) ||
	    pqcp_sovereign_internal_all_zero(
		    attestation->recipe_digest,
		    sizeof(attestation->recipe_digest)) ||
	    pqcp_sovereign_internal_all_zero(
		    attestation->output_digest,
		    sizeof(attestation->output_digest))) {
		return false;
	}
	if (require_statement_digest &&
	    pqcp_sovereign_internal_all_zero(
		    attestation->attestation_digest,
		    sizeof(attestation->attestation_digest))) {
		return false;
	}
	if (require_signature_digest &&
	    pqcp_sovereign_internal_all_zero(
		    attestation->signature_digest,
		    sizeof(attestation->signature_digest))) {
		return false;
	}
	return true;
}

static bool attestation_shape_valid(
	const struct pqcp_sovereign_build_attestation *attestation,
	bool stored)
{
	return attestation != NULL &&
	       attestation->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       attestation_text_valid(attestation) &&
	       attestation->source_revision != 0U &&
	       attestation->built_at_ms != 0U &&
	       attestation->expires_at_ms >
		       attestation->built_at_ms &&
	       attestation->policy_epoch != 0U &&
	       attestation->predicate_mask != 0U &&
	       attestation->risk_score <= 10000U &&
	       attestation_digest_fields_valid(
		       attestation, stored, stored) &&
	       (!stored ||
		(attestation->attestation_id != 0U &&
		 attestation->occupied));
}

static bool text_list_valid(
	const char values[][PQCP_SOVEREIGN_ID_MAX_CHARS],
	size_t count,
	size_t capacity)
{
	if (count > capacity) {
		return false;
	}
	for (size_t index = 0U; index < count; ++index) {
		if (!pqcp_sovereign_internal_text_valid(
			    values[index],
			    PQCP_SOVEREIGN_ID_MAX_CHARS)) {
			return false;
		}
		for (size_t prior = 0U; prior < index; ++prior) {
			if (strncmp(values[index], values[prior],
				    PQCP_SOVEREIGN_ID_MAX_CHARS) == 0) {
				return false;
			}
		}
	}
	return true;
}

static bool digest_set_valid(
	const struct pqcp_sovereign_digest_set *set)
{
	if (set == NULL ||
	    set->count > PQCP_SOVEREIGN_MAX_REVOKED_COMPONENTS) {
		return false;
	}
	for (size_t index = 0U; index < set->count; ++index) {
		if (pqcp_sovereign_internal_all_zero(
			    set->values[index],
			    PQCP_SOVEREIGN_DIGEST_BYTES)) {
			return false;
		}
		for (size_t prior = 0U; prior < index; ++prior) {
			if (pqcp_sovereign_internal_equal(
				    set->values[index],
				    set->values[prior],
				    PQCP_SOVEREIGN_DIGEST_BYTES)) {
				return false;
			}
		}
	}
	return true;
}

static bool license_set_valid(
	const struct pqcp_sovereign_text_set *set)
{
	if (set == NULL ||
	    set->count > PQCP_SOVEREIGN_MAX_ALLOWED_LICENSES) {
		return false;
	}
	for (size_t index = 0U; index < set->count; ++index) {
		if (!pqcp_sovereign_internal_text_valid(
			    set->values[index],
			    PQCP_SOVEREIGN_LABEL_MAX_CHARS)) {
			return false;
		}
		for (size_t prior = 0U; prior < index; ++prior) {
			if (strncmp(
				    set->values[index],
				    set->values[prior],
				    PQCP_SOVEREIGN_LABEL_MAX_CHARS) == 0) {
				return false;
			}
		}
	}
	return true;
}

int pqcp_sovereign_builder_policy_validate(
	const struct pqcp_sovereign_builder_policy *policy)
{
	if (policy == NULL || !policy->initialized ||
	    policy->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    policy->policy_epoch == 0U ||
	    policy->revocation_epoch == 0U ||
	    !pqcp_sovereign_internal_text_valid(
		    policy->tenant_id,
		    sizeof(policy->tenant_id)) ||
	    !pqcp_sovereign_internal_text_valid(
		    policy->target_profile,
		    sizeof(policy->target_profile)) ||
	    policy->trusted_builder_count == 0U ||
	    policy->trusted_builder_count >
		    PQCP_SOVEREIGN_MAX_TRUSTED_BUILDERS ||
	    policy->revoked_builder_count >
		    PQCP_SOVEREIGN_MAX_REVOKED_BUILDERS ||
	    !text_list_valid(
		    policy->trusted_builders,
		    policy->trusted_builder_count,
		    PQCP_SOVEREIGN_MAX_TRUSTED_BUILDERS) ||
	    !text_list_valid(
		    policy->revoked_builders,
		    policy->revoked_builder_count,
		    PQCP_SOVEREIGN_MAX_REVOKED_BUILDERS) ||
	    !digest_set_valid(&policy->revoked_components) ||
	    !license_set_valid(&policy->allowed_licenses) ||
	    policy->required_predicate_mask == 0U ||
	    policy->maximum_attestation_risk > 10000U ||
	    policy->maximum_component_risk > 10000U ||
	    (policy->forbidden_component_flags &
	     ~PQCP_SOVEREIGN_SBOM_KNOWN_FLAGS) != 0U ||
	    (policy->require_known_license &&
	     policy->allowed_licenses.count == 0U)) {
		return -EINVAL;
	}
	for (size_t trusted = 0U;
	     trusted < policy->trusted_builder_count;
	     ++trusted) {
		for (size_t revoked = 0U;
		     revoked < policy->revoked_builder_count;
		     ++revoked) {
			if (strncmp(
				    policy->trusted_builders[trusted],
				    policy->revoked_builders[revoked],
				    PQCP_SOVEREIGN_ID_MAX_CHARS) == 0) {
				return -EACCES;
			}
		}
	}
	return 0;
}

int pqcp_sovereign_build_attestation_canonical_digest(
	const struct pqcp_sovereign_build_attestation *attestation,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t canonical[
		PQCP_SOVEREIGN_ATTESTATION_CANONICAL_BYTES];
	struct attestation_writer writer = {
		.buffer = canonical,
		.capacity = sizeof(canonical),
	};
	int ret;

	if (!attestation_shape_valid(attestation, false) ||
	    output == NULL) {
		return -EINVAL;
	}
	memset(canonical, 0, sizeof(canonical));
	attestation_write_bytes(
		&writer, "PQCP-SOVEREIGN-BUILD-ATTESTATION-V1", 35U);
	attestation_write_u32(
		&writer, attestation->schema_version);
	attestation_write_u64(
		&writer, attestation->attestation_id);
	attestation_write_text(
		&writer, attestation->artifact_id,
		sizeof(attestation->artifact_id));
	attestation_write_text(
		&writer, attestation->builder_id,
		sizeof(attestation->builder_id));
	attestation_write_text(
		&writer, attestation->build_environment,
		sizeof(attestation->build_environment));
	attestation_write_text(
		&writer, attestation->source_uri,
		sizeof(attestation->source_uri));
	attestation_write_u64(
		&writer, attestation->source_revision);
	attestation_write_u64(
		&writer, attestation->built_at_ms);
	attestation_write_u64(
		&writer, attestation->expires_at_ms);
	attestation_write_u64(
		&writer, attestation->policy_epoch);
	attestation_write_u32(
		&writer, attestation->predicate_mask);
	attestation_write_u32(
		&writer, attestation->risk_score);
	attestation_write_bytes(
		&writer, attestation->source_digest,
		sizeof(attestation->source_digest));
	attestation_write_bytes(
		&writer, attestation->recipe_digest,
		sizeof(attestation->recipe_digest));
	attestation_write_bytes(
		&writer, attestation->output_digest,
		sizeof(attestation->output_digest));
	if (writer.error != 0) {
		pqcp_runtime_secure_zero(
			canonical, sizeof(canonical));
		return writer.error;
	}
	ret = pqcp_runtime_internal_sha256(
		canonical, writer.offset, output);
	pqcp_runtime_secure_zero(canonical, sizeof(canonical));
	return ret;
}

static bool builder_in_list(
	const char builders[][PQCP_SOVEREIGN_ID_MAX_CHARS],
	size_t count,
	const char *builder_id)
{
	for (size_t index = 0U; index < count; ++index) {
		if (strncmp(builders[index], builder_id,
			    PQCP_SOVEREIGN_ID_MAX_CHARS) == 0) {
			return true;
		}
	}
	return false;
}

static int attestation_policy_check(
	const struct pqcp_sovereign_build_attestation *attestation,
	const struct pqcp_sovereign_builder_policy *policy,
	uint64_t now_ms)
{
	if (pqcp_sovereign_builder_policy_validate(policy) != 0 ||
	    !attestation_shape_valid(attestation, false) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	if (attestation->built_at_ms > now_ms ||
	    attestation->expires_at_ms <= now_ms) {
		return -ETIME;
	}
	if (attestation->policy_epoch < policy->policy_epoch) {
		return -ESTALE;
	}
	if (!builder_in_list(
		    policy->trusted_builders,
		    policy->trusted_builder_count,
		    attestation->builder_id) ||
	    builder_in_list(
		    policy->revoked_builders,
		    policy->revoked_builder_count,
		    attestation->builder_id)) {
		return -EACCES;
	}
	if (strncmp(attestation->build_environment,
		    policy->target_profile,
		    sizeof(attestation->build_environment)) != 0) {
		return -EXDEV;
	}
	if (((uint64_t)attestation->predicate_mask &
	     policy->required_predicate_mask) !=
		    policy->required_predicate_mask ||
	    attestation->risk_score >
		    policy->maximum_attestation_risk) {
		return -EACCES;
	}
	return 0;
}

static int record_index_by_id_unlocked(
	const struct pqcp_sovereign_build_attestation_store *store,
	uint64_t attestation_id)
{
	for (size_t index = 0U; index < store->capacity;
	     ++index) {
		if (store->records[index].occupied &&
		    store->records[index].attestation_id ==
			    attestation_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int record_index_by_artifact_unlocked(
	const struct pqcp_sovereign_build_attestation_store *store,
	const char *artifact_id,
	uint64_t now_ms,
	bool require_verified)
{
	int selected = -1;

	for (size_t index = 0U; index < store->capacity;
	     ++index) {
		const struct pqcp_sovereign_build_attestation *candidate =
			&store->records[index];

		if (!candidate->occupied ||
		    strncmp(candidate->artifact_id, artifact_id,
			    sizeof(candidate->artifact_id)) != 0 ||
		    candidate->expires_at_ms <= now_ms ||
		    candidate->built_at_ms > now_ms ||
		    (require_verified && !candidate->verified)) {
			continue;
		}
		if (selected < 0 ||
		    candidate->policy_epoch >
			    store->records[selected].policy_epoch ||
		    (candidate->policy_epoch ==
			     store->records[selected].policy_epoch &&
		     candidate->built_at_ms >
			     store->records[selected].built_at_ms)) {
			selected = (int)index;
		}
	}
	return selected >= 0 ? selected : -ENOENT;
}

static int free_record_index_unlocked(
	const struct pqcp_sovereign_build_attestation_store *store)
{
	for (size_t index = 0U; index < store->capacity;
	     ++index) {
		if (!store->records[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int next_attestation_id_unlocked(
	struct pqcp_sovereign_build_attestation_store *store,
	uint64_t requested,
	uint64_t *assigned)
{
	if (requested != 0U) {
		if (record_index_by_id_unlocked(store, requested) >= 0) {
			return -EEXIST;
		}
		if (requested >= store->next_attestation_id) {
			if (requested == UINT64_MAX) {
				return -EOVERFLOW;
			}
			store->next_attestation_id = requested + 1U;
		}
		*assigned = requested;
		return 0;
	}
	*assigned = pqcp_sovereign_internal_next_identifier(
		&store->next_attestation_id);
	return *assigned != 0U ? 0 : -EOVERFLOW;
}

static int insert_record_unlocked(
	struct pqcp_sovereign_build_attestation_store *store,
	const struct pqcp_sovereign_build_attestation *attestation,
	bool verified,
	struct pqcp_sovereign_build_attestation **stored)
{
	struct pqcp_sovereign_build_attestation staged;
	uint64_t assigned_id;
	int index;
	int ret;

	index = free_record_index_unlocked(store);
	if (index < 0) {
		return index;
	}
	staged = *attestation;
	ret = next_attestation_id_unlocked(
		store, staged.attestation_id, &assigned_id);
	if (ret != 0) {
		return ret;
	}
	staged.attestation_id = assigned_id;
	staged.verified = verified;
	staged.occupied = true;
	store->records[index] = staged;
	if (verified) {
		store->verified_count++;
	}
	if (stored != NULL) {
		*stored = &store->records[index];
	}
	return 0;
}

int pqcp_sovereign_build_attestation_store_init(
	struct pqcp_sovereign_build_attestation_store *store,
	struct pqcp_sovereign_build_attestation *records,
	size_t capacity)
{
	if (store == NULL || records == NULL ||
	    capacity == 0U || capacity > INT_MAX) {
		return -EINVAL;
	}
	memset(store, 0, sizeof(*store));
	memset(records, 0, sizeof(*records) * capacity);
	store->schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	store->records = records;
	store->capacity = capacity;
	store->next_attestation_id = 1U;
	k_mutex_init(&store->lock);
	store->initialized = true;
	return 0;
}

int pqcp_sovereign_build_attestation_put(
	struct pqcp_sovereign_build_attestation_store *store,
	const struct pqcp_sovereign_build_attestation *attestation,
	uint64_t now_ms)
{
	struct pqcp_sovereign_build_attestation staged;
	uint8_t computed[PQCP_SOVEREIGN_DIGEST_BYTES];
	int ret;

	if (store == NULL || !store->initialized ||
	    !attestation_shape_valid(attestation, false) ||
	    attestation->occupied || attestation->verified ||
	    now_ms == 0U || attestation->built_at_ms > now_ms ||
	    attestation->expires_at_ms <= now_ms) {
		return -EINVAL;
	}
	staged = *attestation;
	ret = pqcp_sovereign_build_attestation_canonical_digest(
		&staged, computed);
	if (ret != 0) {
		return ret;
	}
	if (!pqcp_sovereign_internal_all_zero(
		    staged.attestation_digest,
		    sizeof(staged.attestation_digest)) &&
	    !pqcp_sovereign_internal_equal(
		    staged.attestation_digest, computed,
		    sizeof(computed))) {
		pqcp_runtime_secure_zero(computed, sizeof(computed));
		return -EBADMSG;
	}
	memcpy(staged.attestation_digest, computed,
	       sizeof(staged.attestation_digest));
	pqcp_runtime_secure_zero(computed, sizeof(computed));
	if (pqcp_sovereign_internal_all_zero(
		    staged.signature_digest,
		    sizeof(staged.signature_digest))) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = insert_record_unlocked(
		store, &staged, false, NULL);
	if (ret != 0) {
		store->rejected_count++;
	}
	(void)k_mutex_unlock(&store->lock);
	return ret;
}

int pqcp_sovereign_build_attestation_find(
	struct pqcp_sovereign_build_attestation_store *store,
	const char *artifact_id,
	uint64_t now_ms,
	struct pqcp_sovereign_build_attestation **attestation)
{
	int index;
	int ret;

	if (store == NULL || !store->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    now_ms == 0U || attestation == NULL) {
		return -EINVAL;
	}
	*attestation = NULL;
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_artifact_unlocked(
		store, artifact_id, now_ms, true);
	if (index >= 0) {
		*attestation = &store->records[index];
	}
	(void)k_mutex_unlock(&store->lock);
	return index >= 0 ? 0 : index;
}

int pqcp_sovereign_build_attestation_verify(
	struct pqcp_sovereign_build_attestation_store *store,
	uint64_t attestation_id,
	const uint8_t expected_output[PQCP_SOVEREIGN_DIGEST_BYTES],
	uint64_t minimum_policy_epoch,
	uint64_t now_ms)
{
	const struct pqcp_sovereign_build_attestation *attestation;
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int index;
	int ret;

	if (store == NULL || !store->initialized ||
	    attestation_id == 0U || expected_output == NULL ||
	    pqcp_sovereign_internal_all_zero(
		    expected_output, PQCP_SOVEREIGN_DIGEST_BYTES) ||
	    minimum_policy_epoch == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = record_index_by_id_unlocked(
		store, attestation_id);
	if (index < 0) {
		(void)k_mutex_unlock(&store->lock);
		return index;
	}
	attestation = &store->records[index];
	if (!attestation->verified) {
		(void)k_mutex_unlock(&store->lock);
		return -EACCES;
	}
	if (attestation->built_at_ms > now_ms ||
	    attestation->expires_at_ms <= now_ms) {
		(void)k_mutex_unlock(&store->lock);
		return -ETIME;
	}
	if (attestation->policy_epoch <
		    minimum_policy_epoch) {
		(void)k_mutex_unlock(&store->lock);
		return -ESTALE;
	}
	if (!pqcp_sovereign_internal_equal(
		    attestation->output_digest,
		    expected_output,
		    PQCP_SOVEREIGN_DIGEST_BYTES)) {
		(void)k_mutex_unlock(&store->lock);
		return -EBADMSG;
	}
	ret = pqcp_sovereign_build_attestation_canonical_digest(
		attestation, digest);
	if (ret == 0 &&
	    !pqcp_sovereign_internal_equal(
		    digest, attestation->attestation_digest,
		    sizeof(digest))) {
		ret = -EBADMSG;
	}
	(void)k_mutex_unlock(&store->lock);
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int verification_key_check(
	struct pqcp_runtime_key_store *key_store,
	const struct pqcp_runtime_key_handle *key,
	uint64_t now_ms)
{
	struct pqcp_runtime_key_metadata metadata;
	int ret;

	if (key_store == NULL ||
	    !pqcp_runtime_key_handle_is_valid(key)) {
		return -EINVAL;
	}
	memset(&metadata, 0, sizeof(metadata));
	ret = pqcp_runtime_key_store_metadata(
		key_store, key, &metadata);
	if (ret != 0) {
		return ret;
	}
	if (!metadata.active ||
	    (metadata.usage &
	     PQCP_RUNTIME_USAGE_VERIFY) == 0U ||
	    (metadata.expires_at_ms != 0U &&
	     metadata.expires_at_ms <= now_ms) ||
	    (metadata.handle.family !=
		     PQCP_RUNTIME_KEY_MLDSA_PUBLIC &&
	     metadata.handle.family !=
		     PQCP_RUNTIME_KEY_MLDSA_KEYPAIR)) {
		return -EACCES;
	}
	return 0;
}

int pqcp_sovereign_build_attestation_verify_signed(
	struct pqcp_sovereign_build_attestation_store *store,
	struct pqcp_runtime_key_store *key_store,
	const struct pqcp_sovereign_signed_attestation *signed_attestation,
	const struct pqcp_sovereign_builder_policy *policy,
	uint64_t now_ms,
	struct pqcp_sovereign_build_attestation **stored)
{
	struct pqcp_sovereign_build_attestation staged;
	uint8_t statement_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t signature_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int ret;

	if (store == NULL || !store->initialized ||
	    key_store == NULL || signed_attestation == NULL ||
	    signed_attestation->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    !attestation_shape_valid(
		    &signed_attestation->statement, false) ||
	    signed_attestation->statement.occupied ||
	    signed_attestation->statement.verified ||
	    signed_attestation->signature_length == 0U ||
	    signed_attestation->signature_length >
		    sizeof(signed_attestation->signature) ||
	    signed_attestation->context_length !=
		    BUILD_ATTESTATION_CONTEXT_BYTES ||
	    memcmp(signed_attestation->context,
		   BUILD_ATTESTATION_CONTEXT,
		   BUILD_ATTESTATION_CONTEXT_BYTES) != 0 ||
	    stored == NULL) {
		return -EINVAL;
	}
	*stored = NULL;
	ret = attestation_policy_check(
		&signed_attestation->statement, policy, now_ms);
	if (ret != 0) {
		return ret;
	}
	ret = verification_key_check(
		key_store, &signed_attestation->verification_key,
		now_ms);
	if (ret != 0) {
		return ret;
	}
	staged = signed_attestation->statement;
	ret = pqcp_sovereign_build_attestation_canonical_digest(
		&staged, statement_digest);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_runtime_internal_sha256(
		signed_attestation->signature,
		signed_attestation->signature_length,
		signature_digest);
	if (ret != 0) {
		goto out;
	}
	if (!pqcp_sovereign_internal_all_zero(
		    staged.attestation_digest,
		    sizeof(staged.attestation_digest)) &&
	    !pqcp_sovereign_internal_equal(
		    staged.attestation_digest,
		    statement_digest,
		    sizeof(statement_digest))) {
		ret = -EBADMSG;
		goto out;
	}
	if (!pqcp_sovereign_internal_all_zero(
		    staged.signature_digest,
		    sizeof(staged.signature_digest)) &&
	    !pqcp_sovereign_internal_equal(
		    staged.signature_digest,
		    signature_digest,
		    sizeof(signature_digest))) {
		ret = -EBADMSG;
		goto out;
	}
	memcpy(staged.attestation_digest, statement_digest,
	       sizeof(staged.attestation_digest));
	memcpy(staged.signature_digest, signature_digest,
	       sizeof(staged.signature_digest));
	ret = pqcp_runtime_key_store_verify(
		key_store, &signed_attestation->verification_key,
		statement_digest, sizeof(statement_digest),
		signed_attestation->context,
		signed_attestation->context_length,
		signed_attestation->signature,
		signed_attestation->signature_length);
	if (ret != 0) {
		goto out;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		goto out;
	}
	ret = insert_record_unlocked(
		store, &staged, true, stored);
	if (ret != 0) {
		store->rejected_count++;
	}
	(void)k_mutex_unlock(&store->lock);
out:
	pqcp_runtime_secure_zero(
		statement_digest, sizeof(statement_digest));
	pqcp_runtime_secure_zero(
		signature_digest, sizeof(signature_digest));
	return ret;
}

int pqcp_sovereign_build_attestation_expire(
	struct pqcp_sovereign_build_attestation_store *store,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t count = 0U;
	int ret;

	if (store == NULL || !store->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < store->capacity;
	     ++index) {
		struct pqcp_sovereign_build_attestation *record =
			&store->records[index];

		if (!record->occupied ||
		    record->expires_at_ms > now_ms) {
			continue;
		}
		pqcp_runtime_secure_zero(record, sizeof(*record));
		if (count != UINT32_MAX) {
			count++;
		}
	}
	(void)k_mutex_unlock(&store->lock);
	*expired_count = count;
	return 0;
}

static int audit_record(
	const struct pqcp_sovereign_build_attestation *record)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int ret;

	if (!attestation_shape_valid(record, true)) {
		return -EBADMSG;
	}
	ret = pqcp_sovereign_build_attestation_canonical_digest(
		record, digest);
	if (ret == 0 &&
	    !pqcp_sovereign_internal_equal(
		    digest, record->attestation_digest,
		    sizeof(digest))) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

int pqcp_sovereign_build_attestation_store_audit(
	struct pqcp_sovereign_build_attestation_store *store)
{
	uint64_t verified = 0U;
	uint64_t highest_id = 0U;
	int ret;

	if (store == NULL || !store->initialized ||
	    store->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    store->records == NULL || store->capacity == 0U ||
	    store->next_attestation_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&store->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < store->capacity;
	     ++index) {
		const struct pqcp_sovereign_build_attestation *record =
			&store->records[index];

		if (!record->occupied) {
			continue;
		}
		ret = audit_record(record);
		if (ret != 0) {
			goto out;
		}
		if (record->verified) {
			verified++;
		}
		if (record->attestation_id > highest_id) {
			highest_id = record->attestation_id;
		}
		for (size_t other = index + 1U;
		     other < store->capacity; ++other) {
			if (store->records[other].occupied &&
			    store->records[other].attestation_id ==
				    record->attestation_id) {
				ret = -EEXIST;
				goto out;
			}
		}
	}
	if (store->verified_count < verified ||
	    (highest_id != UINT64_MAX &&
	     store->next_attestation_id <= highest_id)) {
		ret = -EBADMSG;
	}
out:
	(void)k_mutex_unlock(&store->lock);
	return ret;
}
