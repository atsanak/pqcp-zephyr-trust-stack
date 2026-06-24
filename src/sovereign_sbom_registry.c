/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Allocation-free SBOM ingestion, canonicalization, and dependency closure.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_artifact_internal.h"

#define SBOM_COMPONENT_BODY_BYTES 384U
#define SBOM_DOCUMENT_PREFIX_BYTES 256U

struct sbom_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
};

static void sbom_write_bytes(
	struct sbom_writer *writer,
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

static void sbom_write_u16(
	struct sbom_writer *writer,
	uint16_t value)
{
	uint8_t bytes[2];

	pqcp_runtime_internal_write_u16(bytes, value);
	sbom_write_bytes(writer, bytes, sizeof(bytes));
}

static void sbom_write_u32(
	struct sbom_writer *writer,
	uint32_t value)
{
	uint8_t bytes[4];

	pqcp_runtime_internal_write_u32(bytes, value);
	sbom_write_bytes(writer, bytes, sizeof(bytes));
}

static void sbom_write_u64(
	struct sbom_writer *writer,
	uint64_t value)
{
	uint8_t bytes[8];

	pqcp_runtime_internal_write_u64(bytes, value);
	sbom_write_bytes(writer, bytes, sizeof(bytes));
}

static void sbom_write_text(
	struct sbom_writer *writer,
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
	sbom_write_u16(writer, (uint16_t)length);
	sbom_write_bytes(writer, value, length);
}

static bool document_shape_valid(
	const struct pqcp_sovereign_sbom_document *document,
	bool finalized)
{
	if (document == NULL ||
	    document->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    !pqcp_sovereign_internal_text_valid(
		    document->artifact_id,
		    sizeof(document->artifact_id)) ||
	    !pqcp_sovereign_internal_text_valid(
		    document->format,
		    sizeof(document->format)) ||
	    document->generated_at_ms == 0U ||
	    document->policy_epoch == 0U ||
	    document->component_count >
		    PQCP_SOVEREIGN_MAX_COMPONENTS ||
	    document->vulnerable_count >
		    document->component_count ||
	    document->maximum_vulnerability_score > 10000U) {
		return false;
	}
	if (finalized) {
		return document->complete &&
		       document->occupied &&
		       document->component_count != 0U &&
		       !pqcp_sovereign_internal_all_zero(
			       document->document_digest,
			       sizeof(document->document_digest));
	}
	return !document->complete &&
	       document->component_count == 0U &&
	       document->vulnerable_count == 0U &&
	       document->maximum_vulnerability_score == 0U &&
	       pqcp_sovereign_internal_all_zero(
		       document->document_digest,
		       sizeof(document->document_digest));
}

static bool component_text_valid(
	const struct pqcp_sovereign_sbom_component *component)
{
	return component != NULL &&
	       pqcp_sovereign_internal_text_valid(
		       component->artifact_id,
		       sizeof(component->artifact_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       component->component_id,
		       sizeof(component->component_id)) &&
	       pqcp_sovereign_internal_text_valid(
		       component->name,
		       sizeof(component->name)) &&
	       pqcp_sovereign_internal_text_valid(
		       component->version,
		       sizeof(component->version)) &&
	       pqcp_sovereign_internal_text_valid(
		       component->supplier,
		       sizeof(component->supplier)) &&
	       pqcp_sovereign_internal_text_valid(
		       component->license_id,
		       sizeof(component->license_id));
}

static bool component_shape_valid(
	const struct pqcp_sovereign_sbom_component *component,
	bool stored)
{
	uint64_t valid_dependency_bits;

	if (PQCP_SOVEREIGN_MAX_COMPONENTS >= 64U) {
		valid_dependency_bits = UINT64_MAX;
	} else {
		valid_dependency_bits =
			(1ULL << PQCP_SOVEREIGN_MAX_COMPONENTS) - 1ULL;
	}
	return component != NULL &&
	       component->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       component_text_valid(component) &&
	       component->vulnerability_score <= 10000U &&
	       (component->flags &
		~PQCP_SOVEREIGN_SBOM_KNOWN_FLAGS) == 0U &&
	       (component->dependency_mask &
		~valid_dependency_bits) == 0U &&
	       (!stored ||
		(component->occupied &&
		 !pqcp_sovereign_internal_all_zero(
			 component->component_digest,
			 sizeof(component->component_digest))));
}

int pqcp_sovereign_sbom_component_canonical_digest(
	const struct pqcp_sovereign_sbom_component *component,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t body[SBOM_COMPONENT_BODY_BYTES];
	struct sbom_writer writer = {
		.buffer = body,
		.capacity = sizeof(body),
	};
	int ret;

	if (!component_shape_valid(component, false) ||
	    output == NULL) {
		return -EINVAL;
	}
	memset(body, 0, sizeof(body));
	sbom_write_bytes(
		&writer, "PQCP-SOVEREIGN-SBOM-COMPONENT-V1", 32U);
	sbom_write_u32(&writer, component->schema_version);
	sbom_write_text(&writer, component->artifact_id,
			sizeof(component->artifact_id));
	sbom_write_text(&writer, component->component_id,
			sizeof(component->component_id));
	sbom_write_text(&writer, component->name,
			sizeof(component->name));
	sbom_write_text(&writer, component->version,
			sizeof(component->version));
	sbom_write_text(&writer, component->supplier,
			sizeof(component->supplier));
	sbom_write_text(&writer, component->license_id,
			sizeof(component->license_id));
	sbom_write_u64(&writer, component->dependency_mask);
	sbom_write_u32(
		&writer, component->vulnerability_score);
	sbom_write_u32(&writer, component->flags);
	if (writer.error != 0) {
		pqcp_runtime_secure_zero(body, sizeof(body));
		return writer.error;
	}
	ret = pqcp_runtime_internal_sha256(
		body, writer.offset, output);
	pqcp_runtime_secure_zero(body, sizeof(body));
	return ret;
}

static int document_index_unlocked(
	const struct pqcp_sovereign_sbom_registry *registry,
	const char *artifact_id)
{
	for (size_t index = 0U;
	     index < registry->document_capacity; ++index) {
		const struct pqcp_sovereign_sbom_document *document =
			&registry->documents[index];

		if (document->occupied &&
		    strncmp(document->artifact_id, artifact_id,
			    sizeof(document->artifact_id)) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_document_index_unlocked(
	const struct pqcp_sovereign_sbom_registry *registry)
{
	for (size_t index = 0U;
	     index < registry->document_capacity; ++index) {
		if (!registry->documents[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int component_index_unlocked(
	const struct pqcp_sovereign_sbom_registry *registry,
	const char *artifact_id,
	const char *component_id)
{
	for (size_t index = 0U;
	     index < registry->component_capacity; ++index) {
		const struct pqcp_sovereign_sbom_component *component =
			&registry->components[index];

		if (!component->occupied ||
		    strncmp(component->artifact_id, artifact_id,
			    sizeof(component->artifact_id)) != 0) {
			continue;
		}
		if (strncmp(component->component_id, component_id,
			    sizeof(component->component_id)) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_component_index_unlocked(
	const struct pqcp_sovereign_sbom_registry *registry)
{
	for (size_t index = 0U;
	     index < registry->component_capacity; ++index) {
		if (!registry->components[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static size_t collect_components_unlocked(
	const struct pqcp_sovereign_sbom_registry *registry,
	const char *artifact_id,
	const struct pqcp_sovereign_sbom_component
		*ordered[PQCP_SOVEREIGN_MAX_COMPONENTS])
{
	size_t count = 0U;

	for (size_t index = 0U;
	     index < registry->component_capacity; ++index) {
		const struct pqcp_sovereign_sbom_component *component =
			&registry->components[index];

		if (!component->occupied ||
		    strncmp(component->artifact_id, artifact_id,
			    sizeof(component->artifact_id)) != 0) {
			continue;
		}
		if (count >= PQCP_SOVEREIGN_MAX_COMPONENTS) {
			return SIZE_MAX;
		}
		ordered[count++] = component;
	}
	return count;
}

static int validate_dependency_references(
	const struct pqcp_sovereign_sbom_component
		*const ordered[PQCP_SOVEREIGN_MAX_COMPONENTS],
	size_t count)
{
	uint64_t valid_mask;

	if (count == 0U ||
	    count > PQCP_SOVEREIGN_MAX_COMPONENTS) {
		return -EINVAL;
	}
	valid_mask = count == 64U ?
		UINT64_MAX : ((1ULL << count) - 1ULL);
	for (size_t index = 0U; index < count; ++index) {
		uint64_t dependencies = ordered[index]->dependency_mask;

		if ((dependencies & ~valid_mask) != 0U ||
		    (dependencies & (1ULL << index)) != 0U) {
			return -EBADMSG;
		}
	}
	return 0;
}

static int dependency_visit(
	const struct pqcp_sovereign_sbom_component
		*const ordered[PQCP_SOVEREIGN_MAX_COMPONENTS],
	size_t count,
	size_t index,
	uint64_t *visiting,
	uint64_t *visited,
	uint32_t depth,
	uint32_t *maximum_depth)
{
	uint64_t bit;
	uint64_t dependencies;

	if (index >= count || visiting == NULL ||
	    visited == NULL || maximum_depth == NULL) {
		return -EINVAL;
	}
	bit = 1ULL << index;
	if ((*visiting & bit) != 0U) {
		return -ELOOP;
	}
	if ((*visited & bit) != 0U) {
		return 0;
	}
	if (depth > count) {
		return -ELOOP;
	}
	if (depth > *maximum_depth) {
		*maximum_depth = depth;
	}
	*visiting |= bit;
	dependencies = ordered[index]->dependency_mask;
	for (size_t dependency = 0U;
	     dependency < count; ++dependency) {
		if ((dependencies &
		     (1ULL << dependency)) == 0U) {
			continue;
		}
		{
			int ret = dependency_visit(
				ordered, count, dependency,
				visiting, visited, depth + 1U,
				maximum_depth);

			if (ret != 0) {
				return ret;
			}
		}
	}
	*visiting &= ~bit;
	*visited |= bit;
	return 0;
}

static int validate_dependency_graph(
	const struct pqcp_sovereign_sbom_component
		*const ordered[PQCP_SOVEREIGN_MAX_COMPONENTS],
	size_t count,
	uint32_t *maximum_depth)
{
	uint64_t visiting = 0U;
	uint64_t visited = 0U;
	int ret;

	*maximum_depth = 0U;
	ret = validate_dependency_references(ordered, count);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < count; ++index) {
		ret = dependency_visit(
			ordered, count, index, &visiting,
			&visited, 1U, maximum_depth);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

static int document_digest_unlocked(
	const struct pqcp_sovereign_sbom_registry *registry,
	const struct pqcp_sovereign_sbom_document *document,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	const struct pqcp_sovereign_sbom_component
		*ordered[PQCP_SOVEREIGN_MAX_COMPONENTS] = { 0 };
	uint8_t prefix[SBOM_DOCUMENT_PREFIX_BYTES];
	uint8_t component_digests[PQCP_SOVEREIGN_MAX_COMPONENTS]
				 [PQCP_SOVEREIGN_DIGEST_BYTES];
	const uint8_t *parts[PQCP_SOVEREIGN_MAX_COMPONENTS + 1U];
	size_t lengths[PQCP_SOVEREIGN_MAX_COMPONENTS + 1U];
	struct sbom_writer writer = {
		.buffer = prefix,
		.capacity = sizeof(prefix),
	};
	size_t count;
	int ret;

	if (registry == NULL || document == NULL ||
	    output == NULL) {
		return -EINVAL;
	}
	count = collect_components_unlocked(
		registry, document->artifact_id, ordered);
	if (count == SIZE_MAX || count == 0U ||
	    count != document->component_count) {
		return -EBADMSG;
	}
	memset(prefix, 0, sizeof(prefix));
	memset(component_digests, 0,
	       sizeof(component_digests));
	sbom_write_bytes(
		&writer, "PQCP-SOVEREIGN-SBOM-DOCUMENT-V1", 31U);
	sbom_write_u32(&writer, document->schema_version);
	sbom_write_text(&writer, document->artifact_id,
			sizeof(document->artifact_id));
	sbom_write_text(&writer, document->format,
			sizeof(document->format));
	sbom_write_u64(&writer, document->generated_at_ms);
	sbom_write_u64(&writer, document->policy_epoch);
	sbom_write_u32(&writer, document->component_count);
	sbom_write_u32(&writer, document->vulnerable_count);
	sbom_write_u32(
		&writer, document->maximum_vulnerability_score);
	if (writer.error != 0) {
		return writer.error;
	}
	parts[0] = prefix;
	lengths[0] = writer.offset;
	for (size_t index = 0U; index < count; ++index) {
		ret = pqcp_sovereign_sbom_component_canonical_digest(
			ordered[index], component_digests[index]);
		if (ret != 0 ||
		    !pqcp_sovereign_internal_equal(
			    component_digests[index],
			    ordered[index]->component_digest,
			    PQCP_SOVEREIGN_DIGEST_BYTES)) {
			pqcp_runtime_secure_zero(
				component_digests,
				sizeof(component_digests));
			return ret != 0 ? ret : -EBADMSG;
		}
		parts[index + 1U] = component_digests[index];
		lengths[index + 1U] =
			PQCP_SOVEREIGN_DIGEST_BYTES;
	}
	ret = pqcp_sovereign_internal_hash_parts(
		parts, lengths, count + 1U, output);
	pqcp_runtime_secure_zero(prefix, sizeof(prefix));
	pqcp_runtime_secure_zero(
		component_digests, sizeof(component_digests));
	return ret;
}

int pqcp_sovereign_sbom_document_canonical_digest(
	const struct pqcp_sovereign_sbom_registry *registry,
	const struct pqcp_sovereign_sbom_document *document,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	if (registry == NULL || !registry->initialized ||
	    !document_shape_valid(document, true) ||
	    output == NULL) {
		return -EINVAL;
	}
	return document_digest_unlocked(
		registry, document, output);
}

int pqcp_sovereign_sbom_registry_init(
	struct pqcp_sovereign_sbom_registry *registry,
	struct pqcp_sovereign_sbom_document *documents,
	size_t document_capacity,
	struct pqcp_sovereign_sbom_component *components,
	size_t component_capacity)
{
	if (registry == NULL || documents == NULL ||
	    document_capacity == 0U || components == NULL ||
	    component_capacity == 0U ||
	    document_capacity > INT_MAX ||
	    component_capacity > INT_MAX) {
		return -EINVAL;
	}
	memset(registry, 0, sizeof(*registry));
	memset(documents, 0,
	       sizeof(*documents) * document_capacity);
	memset(components, 0,
	       sizeof(*components) * component_capacity);
	registry->schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	registry->documents = documents;
	registry->document_capacity = document_capacity;
	registry->components = components;
	registry->component_capacity = component_capacity;
	k_mutex_init(&registry->lock);
	registry->initialized = true;
	return 0;
}

int pqcp_sovereign_sbom_begin(
	struct pqcp_sovereign_sbom_registry *registry,
	const struct pqcp_sovereign_sbom_document *document)
{
	struct pqcp_sovereign_sbom_document staged;
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    !document_shape_valid(document, false) ||
	    document->occupied) {
		return -EINVAL;
	}
	staged = *document;
	staged.occupied = true;
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	if (document_index_unlocked(
		    registry, document->artifact_id) >= 0) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return -EEXIST;
	}
	index = free_document_index_unlocked(registry);
	if (index < 0) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return index;
	}
	registry->documents[index] = staged;
	(void)k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_sovereign_sbom_add_component(
	struct pqcp_sovereign_sbom_registry *registry,
	const struct pqcp_sovereign_sbom_component *component)
{
	struct pqcp_sovereign_sbom_component staged;
	struct pqcp_sovereign_sbom_document *document;
	uint8_t computed[PQCP_SOVEREIGN_DIGEST_BYTES];
	int document_index;
	int component_index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    !component_shape_valid(component, false) ||
	    component->occupied) {
		return -EINVAL;
	}
	staged = *component;
	staged.occupied = true;
	ret = pqcp_sovereign_sbom_component_canonical_digest(
		&staged, computed);
	if (ret != 0) {
		return ret;
	}
	if (!pqcp_sovereign_internal_all_zero(
		    component->component_digest,
		    sizeof(component->component_digest)) &&
	    !pqcp_sovereign_internal_equal(
		    component->component_digest, computed,
		    sizeof(computed))) {
		pqcp_runtime_secure_zero(computed, sizeof(computed));
		return -EBADMSG;
	}
	memcpy(staged.component_digest, computed,
	       sizeof(staged.component_digest));
	pqcp_runtime_secure_zero(computed, sizeof(computed));
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	document_index = document_index_unlocked(
		registry, component->artifact_id);
	if (document_index < 0) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return document_index;
	}
	document = &registry->documents[document_index];
	if (document->complete ||
	    document->component_count >=
		    PQCP_SOVEREIGN_MAX_COMPONENTS) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return document->complete ? -EALREADY : -ENOSPC;
	}
	if (component_index_unlocked(
		    registry, component->artifact_id,
		    component->component_id) >= 0) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return -EEXIST;
	}
	component_index =
		free_component_index_unlocked(registry);
	if (component_index < 0) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return component_index;
	}
	registry->components[component_index] = staged;
	document->component_count++;
	if (component->vulnerability_score != 0U) {
		document->vulnerable_count++;
	}
	if (component->vulnerability_score >
	    document->maximum_vulnerability_score) {
		document->maximum_vulnerability_score =
			component->vulnerability_score;
	}
	(void)k_mutex_unlock(&registry->lock);
	return 0;
}

int pqcp_sovereign_sbom_finalize(
	struct pqcp_sovereign_sbom_registry *registry,
	const char *artifact_id,
	uint8_t document_digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	const struct pqcp_sovereign_sbom_component
		*ordered[PQCP_SOVEREIGN_MAX_COMPONENTS] = { 0 };
	struct pqcp_sovereign_sbom_document *document;
	uint8_t computed[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint32_t maximum_depth;
	size_t count;
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    document_digest == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = document_index_unlocked(registry, artifact_id);
	if (index < 0) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return index;
	}
	document = &registry->documents[index];
	if (document->complete) {
		if (!pqcp_sovereign_internal_equal(
			    document->document_digest,
			    document_digest,
			    sizeof(document->document_digest)) &&
		    !pqcp_sovereign_internal_all_zero(
			    document_digest,
			    PQCP_SOVEREIGN_DIGEST_BYTES)) {
			(void)k_mutex_unlock(&registry->lock);
			return -EALREADY;
		}
		memcpy(document_digest, document->document_digest,
		       PQCP_SOVEREIGN_DIGEST_BYTES);
		(void)k_mutex_unlock(&registry->lock);
		return 0;
	}
	count = collect_components_unlocked(
		registry, artifact_id, ordered);
	if (count == SIZE_MAX || count == 0U ||
	    count != document->component_count) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return -EBADMSG;
	}
	ret = validate_dependency_graph(
		ordered, count, &maximum_depth);
	if (ret != 0 || maximum_depth == 0U) {
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return ret != 0 ? ret : -EBADMSG;
	}
	document->complete = true;
	ret = document_digest_unlocked(
		registry, document, computed);
	if (ret != 0) {
		document->complete = false;
		registry->rejection_count++;
		(void)k_mutex_unlock(&registry->lock);
		return ret;
	}
	memcpy(document->document_digest, computed,
	       sizeof(document->document_digest));
	memcpy(document_digest, computed,
	       PQCP_SOVEREIGN_DIGEST_BYTES);
	registry->ingest_count++;
	(void)k_mutex_unlock(&registry->lock);
	pqcp_runtime_secure_zero(computed, sizeof(computed));
	return 0;
}

int pqcp_sovereign_sbom_find(
	struct pqcp_sovereign_sbom_registry *registry,
	const char *artifact_id,
	struct pqcp_sovereign_sbom_document **document)
{
	int index;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    document == NULL) {
		return -EINVAL;
	}
	*document = NULL;
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = document_index_unlocked(registry, artifact_id);
	if (index >= 0) {
		*document = &registry->documents[index];
	}
	(void)k_mutex_unlock(&registry->lock);
	return index >= 0 ? 0 : index;
}

int pqcp_sovereign_sbom_component_risk(
	struct pqcp_sovereign_sbom_registry *registry,
	const char *artifact_id,
	uint32_t forbidden_flags,
	uint32_t *maximum_risk,
	uint32_t *failure_count)
{
	uint32_t risk = 0U;
	uint32_t failures = 0U;
	size_t found = 0U;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    (forbidden_flags &
	     ~PQCP_SOVEREIGN_SBOM_KNOWN_FLAGS) != 0U ||
	    maximum_risk == NULL || failure_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < registry->component_capacity; ++index) {
		const struct pqcp_sovereign_sbom_component *component =
			&registry->components[index];

		if (!component->occupied ||
		    strncmp(component->artifact_id, artifact_id,
			    sizeof(component->artifact_id)) != 0) {
			continue;
		}
		found++;
		if (component->vulnerability_score > risk) {
			risk = component->vulnerability_score;
		}
		if ((component->flags & forbidden_flags) != 0U) {
			failures++;
		}
	}
	(void)k_mutex_unlock(&registry->lock);
	if (found == 0U) {
		return -ENOENT;
	}
	*maximum_risk = risk;
	*failure_count = failures;
	return 0;
}

static bool text_set_contains(
	const struct pqcp_sovereign_text_set *set,
	const char *value)
{
	if (set == NULL || value == NULL) {
		return false;
	}
	for (size_t index = 0U; index < set->count; ++index) {
		if (strncmp(set->values[index], value,
			    PQCP_SOVEREIGN_LABEL_MAX_CHARS) == 0) {
			return true;
		}
	}
	return false;
}

static bool digest_set_contains(
	const struct pqcp_sovereign_digest_set *set,
	const uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	if (set == NULL || digest == NULL) {
		return false;
	}
	for (size_t index = 0U; index < set->count; ++index) {
		if (pqcp_sovereign_internal_equal(
			    set->values[index], digest,
			    PQCP_SOVEREIGN_DIGEST_BYTES)) {
			return true;
		}
	}
	return false;
}

static int closure_expand(
	const struct pqcp_sovereign_sbom_component
		*const ordered[PQCP_SOVEREIGN_MAX_COMPONENTS],
	size_t count,
	size_t index,
	uint32_t depth,
	uint64_t *mask,
	uint32_t *maximum_depth)
{
	uint64_t bit;

	if (index >= count || depth > count ||
	    mask == NULL || maximum_depth == NULL) {
		return -EINVAL;
	}
	bit = 1ULL << index;
	if ((*mask & bit) != 0U) {
		if (depth > *maximum_depth) {
			*maximum_depth = depth;
		}
		return 0;
	}
	*mask |= bit;
	if (depth > *maximum_depth) {
		*maximum_depth = depth;
	}
	for (size_t dependency = 0U;
	     dependency < count; ++dependency) {
		if ((ordered[index]->dependency_mask &
		     (1ULL << dependency)) == 0U) {
			continue;
		}
		{
			int ret = closure_expand(
				ordered, count, dependency,
				depth + 1U, mask, maximum_depth);

			if (ret != 0) {
				return ret;
			}
		}
	}
	return 0;
}

static int closure_digest(
	const struct pqcp_sovereign_sbom_component
		*const ordered[PQCP_SOVEREIGN_MAX_COMPONENTS],
	size_t count,
	uint64_t mask,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t prefix[24];
	const uint8_t *parts[PQCP_SOVEREIGN_MAX_COMPONENTS + 1U];
	size_t lengths[PQCP_SOVEREIGN_MAX_COMPONENTS + 1U];
	size_t part_count = 1U;

	memset(prefix, 0, sizeof(prefix));
	memcpy(prefix, "PQCP-SBOM-CLOSURE-V1", 20U);
	pqcp_runtime_internal_write_u32(
		prefix + 20U, (uint32_t)count);
	parts[0] = prefix;
	lengths[0] = sizeof(prefix);
	for (size_t index = 0U; index < count; ++index) {
		if ((mask & (1ULL << index)) == 0U) {
			continue;
		}
		parts[part_count] =
			ordered[index]->component_digest;
		lengths[part_count] =
			PQCP_SOVEREIGN_DIGEST_BYTES;
		part_count++;
	}
	return pqcp_sovereign_internal_hash_parts(
		parts, lengths, part_count, output);
}

int pqcp_sovereign_sbom_dependency_closure(
	struct pqcp_sovereign_sbom_registry *registry,
	const char *artifact_id,
	const char *root_component_id,
	const struct pqcp_sovereign_builder_policy *trust,
	struct pqcp_sovereign_sbom_closure *closure)
{
	const struct pqcp_sovereign_sbom_component
		*ordered[PQCP_SOVEREIGN_MAX_COMPONENTS] = { 0 };
	uint64_t mask = 0U;
	size_t count;
	int root_index = -1;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    !pqcp_sovereign_internal_text_valid(
		    artifact_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    (root_component_id != NULL &&
	     !pqcp_sovereign_internal_text_valid(
		     root_component_id,
		     PQCP_SOVEREIGN_ID_MAX_CHARS)) ||
	    trust == NULL || closure == NULL ||
	    pqcp_sovereign_builder_policy_validate(trust) != 0) {
		return -EINVAL;
	}
	memset(closure, 0, sizeof(*closure));
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	count = collect_components_unlocked(
		registry, artifact_id, ordered);
	if (count == SIZE_MAX || count == 0U) {
		(void)k_mutex_unlock(&registry->lock);
		return count == 0U ? -ENOENT : -EOVERFLOW;
	}
	ret = validate_dependency_graph(
		ordered, count, &closure->maximum_depth);
	if (ret != 0) {
		(void)k_mutex_unlock(&registry->lock);
		return ret;
	}
	closure->maximum_depth = 0U;
	if (root_component_id != NULL) {
		for (size_t index = 0U; index < count; ++index) {
			if (strncmp(
				    ordered[index]->component_id,
				    root_component_id,
				    sizeof(ordered[index]->
					   component_id)) == 0) {
				root_index = (int)index;
				break;
			}
		}
		if (root_index < 0) {
			(void)k_mutex_unlock(&registry->lock);
			return -ENOENT;
		}
		closure->direct_mask =
			1ULL << (size_t)root_index;
		ret = closure_expand(
			ordered, count, (size_t)root_index, 1U,
			&mask, &closure->maximum_depth);
	} else {
		for (size_t index = 0U; index < count; ++index) {
			if ((ordered[index]->flags &
			     PQCP_SOVEREIGN_SBOM_FLAG_DIRECT) != 0U) {
				closure->direct_mask |= 1ULL << index;
			}
		}
		if (closure->direct_mask == 0U) {
			closure->direct_mask = count == 64U ?
				UINT64_MAX : ((1ULL << count) - 1ULL);
		}
		for (size_t index = 0U; index < count; ++index) {
			if ((closure->direct_mask &
			     (1ULL << index)) == 0U) {
				continue;
			}
			ret = closure_expand(
				ordered, count, index, 1U,
				&mask, &closure->maximum_depth);
			if (ret != 0) {
				break;
			}
		}
	}
	if (ret != 0) {
		(void)k_mutex_unlock(&registry->lock);
		return ret;
	}
	closure->component_mask = mask;
	for (size_t index = 0U; index < count; ++index) {
		const struct pqcp_sovereign_sbom_component *component;

		if ((mask & (1ULL << index)) == 0U) {
			continue;
		}
		component = ordered[index];
		closure->component_count++;
		if (component->vulnerability_score >
		    closure->maximum_risk) {
			closure->maximum_risk =
				component->vulnerability_score;
		}
		if ((component->flags &
		     trust->forbidden_component_flags) != 0U) {
			closure->forbidden_count++;
		}
		if ((component->flags &
		     PQCP_SOVEREIGN_SBOM_FLAG_REVOKED) != 0U ||
		    digest_set_contains(
			    &trust->revoked_components,
			    component->component_digest)) {
			closure->revoked_count++;
		}
		if (trust->require_known_license &&
		    !text_set_contains(
			    &trust->allowed_licenses,
			    component->license_id)) {
			closure->license_failure_count++;
		}
	}
	ret = closure_digest(
		ordered, count, mask, closure->closure_digest);
	(void)k_mutex_unlock(&registry->lock);
	if (ret != 0) {
		return ret;
	}
	if (closure->maximum_risk >
		    trust->maximum_component_risk ||
	    closure->forbidden_count != 0U ||
	    closure->revoked_count != 0U ||
	    closure->license_failure_count != 0U) {
		return -EACCES;
	}
	return 0;
}

int pqcp_sovereign_sbom_validate_artifact_binding(
	struct pqcp_sovereign_sbom_registry *registry,
	const struct pqcp_sovereign_artifact *artifact,
	struct pqcp_sovereign_sbom_document **document)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int ret;

	if (registry == NULL || !registry->initialized ||
	    artifact == NULL || document == NULL) {
		return -EINVAL;
	}
	ret = pqcp_sovereign_sbom_find(
		registry, artifact->artifact_id, document);
	if (ret != 0) {
		return ret;
	}
	if (!(*document)->complete ||
	    (*document)->policy_epoch > artifact->policy_epoch) {
		return -ESTALE;
	}
	ret = pqcp_sovereign_sbom_document_canonical_digest(
		registry, *document, digest);
	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_internal_equal(
		digest, (*document)->document_digest,
		sizeof(digest)) &&
	      pqcp_sovereign_internal_equal(
		      digest, artifact->sbom_digest,
		      sizeof(digest)) ? 0 : -EBADMSG;
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

static int audit_documents_unlocked(
	struct pqcp_sovereign_sbom_registry *registry,
	uint64_t *complete_count)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];

	for (size_t index = 0U;
	     index < registry->document_capacity; ++index) {
		const struct pqcp_sovereign_sbom_document *document =
			&registry->documents[index];

		if (!document->occupied) {
			continue;
		}
		if (!document->complete) {
			if (!document_shape_valid(document, false)) {
				return -EBADMSG;
			}
			continue;
		}
		if (!document_shape_valid(document, true) ||
		    document_digest_unlocked(
			    registry, document, digest) != 0 ||
		    !pqcp_sovereign_internal_equal(
			    digest, document->document_digest,
			    sizeof(digest))) {
			return -EBADMSG;
		}
		(*complete_count)++;
	}
	return 0;
}

static int audit_components_unlocked(
	struct pqcp_sovereign_sbom_registry *registry)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];

	for (size_t index = 0U;
	     index < registry->component_capacity; ++index) {
		const struct pqcp_sovereign_sbom_component *component =
			&registry->components[index];

		if (!component->occupied) {
			continue;
		}
		if (!component_shape_valid(component, true) ||
		    document_index_unlocked(
			    registry, component->artifact_id) < 0 ||
		    pqcp_sovereign_sbom_component_canonical_digest(
			    component, digest) != 0 ||
		    !pqcp_sovereign_internal_equal(
			    digest, component->component_digest,
			    sizeof(digest))) {
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < registry->component_capacity; ++other) {
			const struct pqcp_sovereign_sbom_component *right =
				&registry->components[other];

			if (right->occupied &&
			    strncmp(component->artifact_id,
				    right->artifact_id,
				    sizeof(component->artifact_id)) == 0 &&
			    strncmp(component->component_id,
				    right->component_id,
				    sizeof(component->component_id)) == 0) {
				return -EEXIST;
			}
		}
	}
	return 0;
}

static int audit_graphs_unlocked(
	struct pqcp_sovereign_sbom_registry *registry)
{
	for (size_t document_index = 0U;
	     document_index < registry->document_capacity;
	     ++document_index) {
		const struct pqcp_sovereign_sbom_document *document =
			&registry->documents[document_index];
		const struct pqcp_sovereign_sbom_component
			*ordered[PQCP_SOVEREIGN_MAX_COMPONENTS] = { 0 };
		uint32_t maximum_depth;
		size_t count;
		int ret;

		if (!document->occupied || !document->complete) {
			continue;
		}
		count = collect_components_unlocked(
			registry, document->artifact_id, ordered);
		if (count == SIZE_MAX ||
		    count != document->component_count) {
			return -EBADMSG;
		}
		ret = validate_dependency_graph(
			ordered, count, &maximum_depth);
		if (ret != 0 || maximum_depth == 0U) {
			return ret != 0 ? ret : -EBADMSG;
		}
	}
	return 0;
}

int pqcp_sovereign_sbom_registry_audit(
	struct pqcp_sovereign_sbom_registry *registry)
{
	uint64_t complete_count = 0U;
	int ret;

	if (registry == NULL || !registry->initialized ||
	    registry->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    registry->documents == NULL ||
	    registry->document_capacity == 0U ||
	    registry->components == NULL ||
	    registry->component_capacity == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&registry->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	ret = audit_components_unlocked(registry);
	if (ret == 0) {
		ret = audit_documents_unlocked(
			registry, &complete_count);
	}
	if (ret == 0) {
		ret = audit_graphs_unlocked(registry);
	}
	if (ret == 0 &&
	    registry->ingest_count < complete_count) {
		ret = -EBADMSG;
	}
	(void)k_mutex_unlock(&registry->lock);
	return ret;
}
