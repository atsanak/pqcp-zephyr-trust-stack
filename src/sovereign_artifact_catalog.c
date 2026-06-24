/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free sovereign artifact catalog and canonical identity.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_artifact_internal.h"

struct canonical_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
};

static void writer_bytes(
	struct canonical_writer *writer,
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

static void writer_u8(
	struct canonical_writer *writer,
	uint8_t value)
{
	writer_bytes(writer, &value, sizeof(value));
}

static void writer_u32(
	struct canonical_writer *writer,
	uint32_t value)
{
	uint8_t encoded[4];

	pqcp_runtime_internal_write_u32(encoded, value);
	writer_bytes(writer, encoded, sizeof(encoded));
}

static void writer_u64(
	struct canonical_writer *writer,
	uint64_t value)
{
	uint8_t encoded[8];

	pqcp_runtime_internal_write_u64(encoded, value);
	writer_bytes(writer, encoded, sizeof(encoded));
}

static void writer_text(
	struct canonical_writer *writer,
	const char *value,
	size_t capacity)
{
	size_t length;

	if (writer == NULL || writer->error != 0) {
		return;
	}
	if (!pqcp_sovereign_internal_text_valid(
		    value, capacity)) {
		writer->error = -EINVAL;
		return;
	}
	length = strnlen(value, capacity);
	if (length > UINT16_MAX) {
		writer->error = -EOVERFLOW;
		return;
	}
	{
		uint8_t encoded[2];

		pqcp_runtime_internal_write_u16(
			encoded, (uint16_t)length);
		writer_bytes(writer, encoded, sizeof(encoded));
	}
	writer_bytes(writer, value, length);
}

bool pqcp_sovereign_internal_all_zero(
	const uint8_t *value,
	size_t length)
{
	uint8_t aggregate = 0U;

	if (value == NULL && length != 0U) {
		return true;
	}
	for (size_t index = 0U; index < length; ++index) {
		aggregate |= value[index];
	}
	return aggregate == 0U;
}

bool pqcp_sovereign_internal_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	if ((left == NULL || right == NULL) && length != 0U) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

bool pqcp_sovereign_internal_text_valid(
	const char *value,
	size_t capacity)
{
	return value != NULL && capacity > 1U &&
	       value[0] != '\0' &&
	       strnlen(value, capacity) < capacity;
}

int pqcp_sovereign_internal_copy_text(
	char *destination,
	size_t capacity,
	const char *source)
{
	if (destination == NULL || capacity == 0U ||
	    !pqcp_sovereign_internal_text_valid(
		    source, capacity)) {
		return -EINVAL;
	}
	memset(destination, 0, capacity);
	memcpy(destination, source,
	       strnlen(source, capacity));
	return 0;
}

uint32_t pqcp_sovereign_internal_next_generation(
	uint32_t *generation)
{
	uint32_t current;

	if (generation == NULL) {
		return 0U;
	}
	current = *generation;
	if (current == 0U) {
		current = 1U;
	}
	if (current == UINT32_MAX) {
		*generation = 1U;
	} else {
		*generation = current + 1U;
	}
	return current;
}

uint64_t pqcp_sovereign_internal_next_identifier(
	uint64_t *identifier)
{
	uint64_t current;

	if (identifier == NULL) {
		return 0U;
	}
	current = *identifier;
	if (current == 0U) {
		current = 1U;
	}
	if (current == UINT64_MAX) {
		*identifier = 1U;
	} else {
		*identifier = current + 1U;
	}
	return current;
}

int pqcp_sovereign_internal_hash_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	if (parts == NULL || lengths == NULL ||
	    part_count == 0U || output == NULL) {
		return -EINVAL;
	}
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, part_count, output);
}

bool pqcp_sovereign_internal_artifact_state_valid(
	enum pqcp_sovereign_artifact_state state)
{
	return state >= PQCP_SOVEREIGN_ARTIFACT_REGISTERED &&
	       state <= PQCP_SOVEREIGN_ARTIFACT_REVOKED;
}

bool pqcp_sovereign_internal_artifact_transition_valid(
	enum pqcp_sovereign_artifact_state current,
	enum pqcp_sovereign_artifact_state next)
{
	if (!pqcp_sovereign_internal_artifact_state_valid(
		    current) ||
	    !pqcp_sovereign_internal_artifact_state_valid(
		    next) ||
	    current == next) {
		return false;
	}
	if (next == PQCP_SOVEREIGN_ARTIFACT_REVOKED) {
		return current != PQCP_SOVEREIGN_ARTIFACT_REVOKED;
	}
	if (next == PQCP_SOVEREIGN_ARTIFACT_QUARANTINED) {
		return current != PQCP_SOVEREIGN_ARTIFACT_REVOKED &&
		       current != PQCP_SOVEREIGN_ARTIFACT_QUARANTINED;
	}
	switch (current) {
	case PQCP_SOVEREIGN_ARTIFACT_REGISTERED:
		return next == PQCP_SOVEREIGN_ARTIFACT_ATTESTED;
	case PQCP_SOVEREIGN_ARTIFACT_ATTESTED:
		return next == PQCP_SOVEREIGN_ARTIFACT_APPROVED;
	case PQCP_SOVEREIGN_ARTIFACT_APPROVED:
		return next == PQCP_SOVEREIGN_ARTIFACT_RELEASED;
	case PQCP_SOVEREIGN_ARTIFACT_QUARANTINED:
		return next == PQCP_SOVEREIGN_ARTIFACT_REGISTERED;
	case PQCP_SOVEREIGN_ARTIFACT_RELEASED:
	case PQCP_SOVEREIGN_ARTIFACT_REVOKED:
	default:
		return false;
	}
}

static bool artifact_text_valid(
	const struct pqcp_sovereign_artifact *artifact)
{
	return artifact != NULL &&
	       pqcp_sovereign_internal_text_valid(
		       artifact->artifact_id,
		       sizeof(artifact->artifact_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       artifact->tenant_id,
		       sizeof(artifact->tenant_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       artifact->name,
		       sizeof(artifact->name)) &&
	       pqcp_sovereign_internal_text_valid(
		       artifact->version,
		       sizeof(artifact->version)) &&
	       pqcp_sovereign_internal_text_valid(
		       artifact->supplier,
		       sizeof(artifact->supplier)) &&
	       pqcp_sovereign_internal_text_valid(
		       artifact->media_type,
		       sizeof(artifact->media_type));
}

static bool artifact_digest_valid(
	const struct pqcp_sovereign_artifact *artifact)
{
	return artifact != NULL &&
	       !pqcp_sovereign_internal_all_zero(
		       artifact->content_digest,
		       sizeof(artifact->content_digest)) &&
	       !pqcp_sovereign_internal_all_zero(
		       artifact->sbom_digest,
		       sizeof(artifact->sbom_digest)) &&
	       !pqcp_sovereign_internal_all_zero(
		       artifact->provenance_digest,
		       sizeof(artifact->provenance_digest)) &&
	       !pqcp_sovereign_internal_all_zero(
		       artifact->signature_digest,
		       sizeof(artifact->signature_digest));
}

static bool artifact_shape_valid(
	const struct pqcp_sovereign_artifact *artifact)
{
	return artifact != NULL &&
	       artifact->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       artifact_text_valid(artifact) &&
	       artifact_digest_valid(artifact) &&
	       artifact->size_bytes != 0U &&
	       artifact->created_at_ms != 0U &&
	       artifact->policy_epoch != 0U &&
	       artifact->signing_epoch != 0U &&
	       artifact->release_sequence != 0U &&
	       artifact->risk_score <= 10000U &&
	       pqcp_sovereign_internal_artifact_state_valid(
		       artifact->state);
}

int pqcp_sovereign_artifact_canonical_digest(
	const struct pqcp_sovereign_artifact *artifact,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t canonical[PQCP_SOVEREIGN_ARTIFACT_CANONICAL_BYTES];
	struct canonical_writer writer = {
		.buffer = canonical,
		.capacity = sizeof(canonical),
	};
	int ret;

	if (!artifact_shape_valid(artifact) || output == NULL) {
		return -EINVAL;
	}
	memset(canonical, 0, sizeof(canonical));
	writer_bytes(&writer, "PQCP-SOVEREIGN-ARTIFACT-V1", 27U);
	writer_u32(&writer, artifact->schema_version);
	writer_u32(&writer, artifact->generation);
	writer_text(&writer, artifact->artifact_id,
		    sizeof(artifact->artifact_id));
	writer_text(&writer, artifact->tenant_id,
		    sizeof(artifact->tenant_id));
	writer_text(&writer, artifact->name,
		    sizeof(artifact->name));
	writer_text(&writer, artifact->version,
		    sizeof(artifact->version));
	writer_text(&writer, artifact->supplier,
		    sizeof(artifact->supplier));
	writer_text(&writer, artifact->media_type,
		    sizeof(artifact->media_type));
	writer_u64(&writer, artifact->size_bytes);
	writer_u64(&writer, artifact->created_at_ms);
	writer_u64(&writer, artifact->policy_epoch);
	writer_u64(&writer, artifact->signing_epoch);
	writer_u64(&writer, artifact->release_sequence);
	writer_u32(&writer, artifact->risk_score);
	writer_u32(&writer, (uint32_t)artifact->state);
	writer_bytes(&writer, artifact->content_digest,
		     sizeof(artifact->content_digest));
	writer_bytes(&writer, artifact->sbom_digest,
		     sizeof(artifact->sbom_digest));
	writer_bytes(&writer, artifact->provenance_digest,
		     sizeof(artifact->provenance_digest));
	writer_bytes(&writer, artifact->signature_digest,
		     sizeof(artifact->signature_digest));
	writer_u8(&writer, artifact->reproducible ? 1U : 0U);
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

static int find_index_unlocked(
	const struct pqcp_sovereign_artifact_catalog *catalog,
	const char *artifact_id)
{
	if (catalog == NULL || artifact_id == NULL) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < catalog->capacity;
	     ++index) {
		const struct pqcp_sovereign_artifact *candidate =
			&catalog->artifacts[index];

		if (candidate->occupied &&
		    strncmp(candidate->artifact_id, artifact_id,
			    sizeof(candidate->artifact_id)) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_index_unlocked(
	const struct pqcp_sovereign_artifact_catalog *catalog)
{
	for (size_t index = 0U; index < catalog->capacity;
	     ++index) {
		if (!catalog->artifacts[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int duplicate_content_unlocked(
	const struct pqcp_sovereign_artifact_catalog *catalog,
	const struct pqcp_sovereign_artifact *artifact)
{
	for (size_t index = 0U; index < catalog->capacity;
	     ++index) {
		const struct pqcp_sovereign_artifact *candidate =
			&catalog->artifacts[index];

		if (!candidate->occupied) {
			continue;
		}
		if (strncmp(candidate->tenant_id,
			    artifact->tenant_id,
			    sizeof(candidate->tenant_id)) == 0 &&
		    strncmp(candidate->name, artifact->name,
			    sizeof(candidate->name)) == 0 &&
		    pqcp_sovereign_internal_equal(
			    candidate->content_digest,
			    artifact->content_digest,
			    sizeof(candidate->content_digest))) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static uint64_t highest_release_unlocked(
	const struct pqcp_sovereign_artifact_catalog *catalog,
	const char *tenant_id,
	const char *name)
{
	uint64_t highest = 0U;

	for (size_t index = 0U; index < catalog->capacity;
	     ++index) {
		const struct pqcp_sovereign_artifact *candidate =
			&catalog->artifacts[index];

		if (!candidate->occupied ||
		    strncmp(candidate->tenant_id, tenant_id,
			    sizeof(candidate->tenant_id)) != 0 ||
		    strncmp(candidate->name, name,
			    sizeof(candidate->name)) != 0) {
			continue;
		}
		if (candidate->release_sequence > highest) {
			highest = candidate->release_sequence;
		}
	}
	return highest;
}

int pqcp_sovereign_artifact_catalog_init(
	struct pqcp_sovereign_artifact_catalog *catalog,
	struct pqcp_sovereign_artifact *artifacts,
	size_t capacity)
{
	if (catalog == NULL || artifacts == NULL ||
	    capacity == 0U || capacity > INT_MAX) {
		return -EINVAL;
	}
	memset(catalog, 0, sizeof(*catalog));
	memset(artifacts, 0, sizeof(*artifacts) * capacity);
	catalog->schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	catalog->artifacts = artifacts;
	catalog->capacity = capacity;
	catalog->next_generation = 1U;
	k_mutex_init(&catalog->lock);
	catalog->initialized = true;
	return 0;
}

int pqcp_sovereign_artifact_register(
	struct pqcp_sovereign_artifact_catalog *catalog,
	const struct pqcp_sovereign_artifact *artifact,
	uint64_t now_ms)
{
	struct pqcp_sovereign_artifact staged;
	uint8_t canonical[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint64_t highest;
	int index;
	int ret;

	if (catalog == NULL || !catalog->initialized ||
	    !artifact_shape_valid(artifact) ||
	    artifact->state !=
		    PQCP_SOVEREIGN_ARTIFACT_REGISTERED ||
	    artifact->occupied || artifact->generation != 0U ||
	    now_ms == 0U || artifact->created_at_ms > now_ms) {
		return -EINVAL;
	}
	staged = *artifact;
	staged.generation = catalog->next_generation == 0U ?
		1U : catalog->next_generation;
	staged.occupied = true;
	ret = pqcp_sovereign_artifact_canonical_digest(
		&staged, canonical);
	if (ret != 0 ||
	    pqcp_sovereign_internal_all_zero(
		    canonical, sizeof(canonical))) {
		return ret != 0 ? ret : -EBADMSG;
	}
	ret = k_mutex_lock(&catalog->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = find_index_unlocked(
		catalog, staged.artifact_id);
	if (index >= 0 ||
	    duplicate_content_unlocked(catalog, &staged) >= 0) {
		(void)k_mutex_unlock(&catalog->lock);
		return -EEXIST;
	}
	highest = highest_release_unlocked(
		catalog, staged.tenant_id, staged.name);
	if (staged.release_sequence <= highest) {
		(void)k_mutex_unlock(&catalog->lock);
		return -ESTALE;
	}
	index = free_index_unlocked(catalog);
	if (index < 0) {
		(void)k_mutex_unlock(&catalog->lock);
		return index;
	}
	staged.generation =
		pqcp_sovereign_internal_next_generation(
			&catalog->next_generation);
	catalog->artifacts[index] = staged;
	catalog->registration_count++;
	(void)k_mutex_unlock(&catalog->lock);
	pqcp_runtime_secure_zero(canonical, sizeof(canonical));
	return 0;
}

int pqcp_sovereign_artifact_find(
	struct pqcp_sovereign_artifact_catalog *catalog,
	const char *artifact_id,
	struct pqcp_sovereign_artifact **artifact)
{
	int index;
	int ret;

	if (catalog == NULL || !catalog->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    artifact == NULL) {
		return -EINVAL;
	}
	*artifact = NULL;
	ret = k_mutex_lock(&catalog->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = find_index_unlocked(catalog, artifact_id);
	if (index >= 0) {
		*artifact = &catalog->artifacts[index];
	}
	(void)k_mutex_unlock(&catalog->lock);
	return index >= 0 ? 0 : index;
}

int pqcp_sovereign_artifact_find_const(
	const struct pqcp_sovereign_artifact_catalog *catalog,
	const char *artifact_id,
	const struct pqcp_sovereign_artifact **artifact)
{
	struct pqcp_sovereign_artifact_catalog *mutable_catalog;
	int index;
	int ret;

	if (catalog == NULL || !catalog->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    artifact == NULL) {
		return -EINVAL;
	}
	*artifact = NULL;
	mutable_catalog =
		(struct pqcp_sovereign_artifact_catalog *)catalog;
	ret = k_mutex_lock(&mutable_catalog->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = find_index_unlocked(catalog, artifact_id);
	if (index >= 0) {
		*artifact = &catalog->artifacts[index];
	}
	(void)k_mutex_unlock(&mutable_catalog->lock);
	return index >= 0 ? 0 : index;
}

int pqcp_sovereign_artifact_find_by_content(
	const struct pqcp_sovereign_artifact_catalog *catalog,
	const uint8_t content_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	const struct pqcp_sovereign_artifact **artifact)
{
	struct pqcp_sovereign_artifact_catalog *mutable_catalog;
	int ret;

	if (catalog == NULL || !catalog->initialized ||
	    content_digest == NULL || artifact == NULL ||
	    pqcp_sovereign_internal_all_zero(
		    content_digest, PQCP_SOVEREIGN_DIGEST_BYTES)) {
		return -EINVAL;
	}
	*artifact = NULL;
	mutable_catalog =
		(struct pqcp_sovereign_artifact_catalog *)catalog;
	ret = k_mutex_lock(&mutable_catalog->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < catalog->capacity;
	     ++index) {
		const struct pqcp_sovereign_artifact *candidate =
			&catalog->artifacts[index];

		if (candidate->occupied &&
		    pqcp_sovereign_internal_equal(
			    candidate->content_digest,
			    content_digest,
			    PQCP_SOVEREIGN_DIGEST_BYTES)) {
			*artifact = candidate;
			break;
		}
	}
	(void)k_mutex_unlock(&mutable_catalog->lock);
	return *artifact != NULL ? 0 : -ENOENT;
}

int pqcp_sovereign_artifact_highest_release(
	const struct pqcp_sovereign_artifact_catalog *catalog,
	const char *tenant_id,
	const char *name,
	uint64_t *release_sequence)
{
	struct pqcp_sovereign_artifact_catalog *mutable_catalog;
	int ret;

	if (catalog == NULL || !catalog->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    tenant_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_internal_text_valid(
		    name, PQCP_SOVEREIGN_NAME_MAX_CHARS) ||
	    release_sequence == NULL) {
		return -EINVAL;
	}
	mutable_catalog =
		(struct pqcp_sovereign_artifact_catalog *)catalog;
	ret = k_mutex_lock(&mutable_catalog->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	*release_sequence = highest_release_unlocked(
		catalog, tenant_id, name);
	(void)k_mutex_unlock(&mutable_catalog->lock);
	return *release_sequence != 0U ? 0 : -ENOENT;
}

int pqcp_sovereign_artifact_transition(
	struct pqcp_sovereign_artifact_catalog *catalog,
	const char *artifact_id,
	enum pqcp_sovereign_artifact_state state,
	uint64_t policy_epoch)
{
	struct pqcp_sovereign_artifact *artifact;
	int index;
	int ret;

	if (catalog == NULL || !catalog->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !pqcp_sovereign_internal_artifact_state_valid(state) ||
	    policy_epoch == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&catalog->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = find_index_unlocked(catalog, artifact_id);
	if (index < 0) {
		(void)k_mutex_unlock(&catalog->lock);
		return index;
	}
	artifact = &catalog->artifacts[index];
	if (policy_epoch < artifact->policy_epoch) {
		(void)k_mutex_unlock(&catalog->lock);
		return -ESTALE;
	}
	if (!pqcp_sovereign_internal_artifact_transition_valid(
		    artifact->state, state)) {
		(void)k_mutex_unlock(&catalog->lock);
		return -EPERM;
	}
	artifact->state = state;
	artifact->policy_epoch = policy_epoch;
	(void)k_mutex_unlock(&catalog->lock);
	return 0;
}

int pqcp_sovereign_artifact_quarantine(
	struct pqcp_sovereign_artifact_catalog *catalog,
	const char *artifact_id,
	uint32_t risk_score)
{
	struct pqcp_sovereign_artifact *artifact;
	int index;
	int ret;

	if (catalog == NULL || !catalog->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    risk_score > 10000U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&catalog->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = find_index_unlocked(catalog, artifact_id);
	if (index < 0) {
		(void)k_mutex_unlock(&catalog->lock);
		return index;
	}
	artifact = &catalog->artifacts[index];
	if (artifact->state == PQCP_SOVEREIGN_ARTIFACT_REVOKED) {
		(void)k_mutex_unlock(&catalog->lock);
		return -EPERM;
	}
	if (artifact->state !=
		    PQCP_SOVEREIGN_ARTIFACT_QUARANTINED) {
		catalog->quarantine_count++;
	}
	artifact->state =
		PQCP_SOVEREIGN_ARTIFACT_QUARANTINED;
	if (risk_score > artifact->risk_score) {
		artifact->risk_score = risk_score;
	}
	(void)k_mutex_unlock(&catalog->lock);
	return 0;
}

static int audit_duplicate_ids(
	const struct pqcp_sovereign_artifact_catalog *catalog)
{
	for (size_t left = 0U; left < catalog->capacity;
	     ++left) {
		if (!catalog->artifacts[left].occupied) {
			continue;
		}
		for (size_t right = left + 1U;
		     right < catalog->capacity; ++right) {
			if (!catalog->artifacts[right].occupied) {
				continue;
			}
			if (strncmp(
				    catalog->artifacts[left].artifact_id,
				    catalog->artifacts[right].artifact_id,
				    PQCP_SOVEREIGN_ID_MAX_CHARS) == 0) {
				return -EEXIST;
			}
		}
	}
	return 0;
}

static int audit_release_sequences(
	const struct pqcp_sovereign_artifact_catalog *catalog)
{
	for (size_t left = 0U; left < catalog->capacity;
	     ++left) {
		const struct pqcp_sovereign_artifact *a =
			&catalog->artifacts[left];

		if (!a->occupied) {
			continue;
		}
		for (size_t right = left + 1U;
		     right < catalog->capacity; ++right) {
			const struct pqcp_sovereign_artifact *b =
				&catalog->artifacts[right];

			if (!b->occupied ||
			    strncmp(a->tenant_id, b->tenant_id,
				    sizeof(a->tenant_id)) != 0 ||
			    strncmp(a->name, b->name,
				    sizeof(a->name)) != 0) {
				continue;
			}
			if (a->release_sequence ==
			    b->release_sequence) {
				return -EEXIST;
			}
		}
	}
	return 0;
}

int pqcp_sovereign_artifact_catalog_audit(
	struct pqcp_sovereign_artifact_catalog *catalog)
{
	uint64_t occupied_count = 0U;
	uint64_t quarantine_count = 0U;
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int ret;

	if (catalog == NULL || !catalog->initialized ||
	    catalog->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    catalog->artifacts == NULL ||
	    catalog->capacity == 0U ||
	    catalog->next_generation == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&catalog->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < catalog->capacity;
	     ++index) {
		const struct pqcp_sovereign_artifact *artifact =
			&catalog->artifacts[index];

		if (!artifact->occupied) {
			continue;
		}
		if (!artifact_shape_valid(artifact) ||
		    artifact->generation == 0U) {
			ret = -EBADMSG;
			goto out;
		}
		ret = pqcp_sovereign_artifact_canonical_digest(
			artifact, digest);
		if (ret != 0 ||
		    pqcp_sovereign_internal_all_zero(
			    digest, sizeof(digest))) {
			ret = ret != 0 ? ret : -EBADMSG;
			goto out;
		}
		occupied_count++;
		if (artifact->state ==
		    PQCP_SOVEREIGN_ARTIFACT_QUARANTINED) {
			quarantine_count++;
		}
	}
	ret = audit_duplicate_ids(catalog);
	if (ret == 0) {
		ret = audit_release_sequences(catalog);
	}
	if (ret == 0 &&
	    (catalog->registration_count < occupied_count ||
	     catalog->quarantine_count < quarantine_count)) {
		ret = -EBADMSG;
	}
out:
	(void)k_mutex_unlock(&catalog->lock);
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}
