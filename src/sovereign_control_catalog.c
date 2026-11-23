/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free interoperability control catalog.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/sovereign_runtime.h>

#include "sovereign_artifact_internal.h"

#define CONTROL_WEIGHT_MAX 10000U

static int catalog_lock(struct pqcp_sovereign_control_catalog *catalog)
{
	if (catalog == NULL || !catalog->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(&catalog->lock, K_FOREVER);
}

static void catalog_unlock(
	struct pqcp_sovereign_control_catalog *catalog)
{
	(void)k_mutex_unlock(&catalog->lock);
}

static bool mapping_shape_valid(
	const struct pqcp_sovereign_control_mapping *mapping)
{
	return mapping != NULL &&
	       mapping->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       mapping->mapping_id != 0U &&
	       pqcp_sovereign_internal_text_valid(
		       mapping->internal_control,
		       sizeof(mapping->internal_control)) &&
	       pqcp_sovereign_internal_text_valid(
		       mapping->framework, sizeof(mapping->framework)) &&
	       pqcp_sovereign_internal_text_valid(
		       mapping->external_control,
		       sizeof(mapping->external_control)) &&
	       pqcp_sovereign_internal_text_valid(
		       mapping->evidence_type,
		       sizeof(mapping->evidence_type)) &&
	       mapping->policy_epoch != 0U &&
	       mapping->weight_basis_points != 0U &&
	       mapping->weight_basis_points <= CONTROL_WEIGHT_MAX;
}

static int mapping_index_by_id_locked(
	const struct pqcp_sovereign_control_catalog *catalog,
	uint32_t mapping_id)
{
	size_t index;

	if (mapping_id == 0U) {
		return -EINVAL;
	}
	for (index = 0U; index < catalog->capacity; ++index) {
		if (catalog->mappings[index].mapping_id == mapping_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int mapping_index_by_scope_locked(
	const struct pqcp_sovereign_control_catalog *catalog,
	const char *internal_control,
	const char *framework)
{
	size_t index;

	for (index = 0U; index < catalog->capacity; ++index) {
		const struct pqcp_sovereign_control_mapping *mapping =
			&catalog->mappings[index];

		if (mapping->mapping_id != 0U &&
		    strcmp(mapping->internal_control,
			   internal_control) == 0 &&
		    strcmp(mapping->framework, framework) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int free_mapping_index_locked(
	const struct pqcp_sovereign_control_catalog *catalog)
{
	size_t index;

	for (index = 0U; index < catalog->capacity; ++index) {
		if (catalog->mappings[index].mapping_id == 0U) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static bool mapping_identity_equal(
	const struct pqcp_sovereign_control_mapping *left,
	const struct pqcp_sovereign_control_mapping *right)
{
	return strcmp(left->internal_control,
		      right->internal_control) == 0 &&
	       strcmp(left->framework, right->framework) == 0;
}

static bool mapping_content_equal(
	const struct pqcp_sovereign_control_mapping *left,
	const struct pqcp_sovereign_control_mapping *right)
{
	return mapping_identity_equal(left, right) &&
	       strcmp(left->external_control,
		      right->external_control) == 0 &&
	       strcmp(left->evidence_type,
		      right->evidence_type) == 0 &&
	       left->policy_epoch == right->policy_epoch &&
	       left->weight_basis_points ==
		       right->weight_basis_points &&
	       left->mandatory == right->mandatory &&
	       left->enabled == right->enabled;
}

static int copy_mapping(
	struct pqcp_sovereign_control_mapping *destination,
	const struct pqcp_sovereign_control_mapping *source,
	uint32_t mapping_id)
{
	int ret;

	memset(destination, 0, sizeof(*destination));
	destination->schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	destination->mapping_id = mapping_id;
	ret = pqcp_sovereign_internal_copy_text(
		destination->internal_control,
		sizeof(destination->internal_control),
		source->internal_control);
	if (ret == 0) {
		ret = pqcp_sovereign_internal_copy_text(
			destination->framework,
			sizeof(destination->framework),
			source->framework);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_internal_copy_text(
			destination->external_control,
			sizeof(destination->external_control),
			source->external_control);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_internal_copy_text(
			destination->evidence_type,
			sizeof(destination->evidence_type),
			source->evidence_type);
	}
	if (ret != 0) {
		memset(destination, 0, sizeof(*destination));
		return ret;
	}
	destination->policy_epoch = source->policy_epoch;
	destination->weight_basis_points =
		source->weight_basis_points;
	destination->mandatory = source->mandatory;
	destination->enabled = source->enabled;
	return 0;
}

int pqcp_sovereign_control_catalog_init(
	struct pqcp_sovereign_control_catalog *catalog,
	struct pqcp_sovereign_control_mapping *mappings,
	size_t capacity)
{
	if (catalog == NULL || mappings == NULL ||
	    capacity == 0U || capacity > UINT32_MAX) {
		return -EINVAL;
	}
	memset(catalog, 0, sizeof(*catalog));
	memset(mappings, 0, capacity * sizeof(*mappings));
	catalog->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	catalog->mappings = mappings;
	catalog->capacity = capacity;
	catalog->next_mapping_id = 1U;
	catalog->generation = 1U;
	k_mutex_init(&catalog->lock);
	catalog->initialized = true;
	return 0;
}

int pqcp_sovereign_control_mapping_put(
	struct pqcp_sovereign_control_catalog *catalog,
	const struct pqcp_sovereign_control_mapping *mapping)
{
	struct pqcp_sovereign_control_mapping candidate;
	int identity_index;
	int index;
	int ret;

	if (mapping == NULL ||
	    !pqcp_sovereign_internal_text_valid(
		    mapping->internal_control,
		    sizeof(mapping->internal_control)) ||
	    !pqcp_sovereign_internal_text_valid(
		    mapping->framework, sizeof(mapping->framework)) ||
	    !pqcp_sovereign_internal_text_valid(
		    mapping->external_control,
		    sizeof(mapping->external_control)) ||
	    !pqcp_sovereign_internal_text_valid(
		    mapping->evidence_type,
		    sizeof(mapping->evidence_type)) ||
	    mapping->policy_epoch == 0U ||
	    mapping->weight_basis_points == 0U ||
	    mapping->weight_basis_points > CONTROL_WEIGHT_MAX) {
		return -EINVAL;
	}
	ret = catalog_lock(catalog);
	if (ret != 0) {
		return ret;
	}
	if (catalog->generation == UINT64_MAX) {
		catalog_unlock(catalog);
		return -EOVERFLOW;
	}
	identity_index = mapping_index_by_scope_locked(
		catalog, mapping->internal_control,
		mapping->framework);
	if (mapping->mapping_id == 0U) {
		if (identity_index >= 0) {
			catalog_unlock(catalog);
			return -EEXIST;
		}
		if (catalog->next_mapping_id == 0U ||
		    catalog->next_mapping_id == UINT32_MAX) {
			catalog_unlock(catalog);
			return -EOVERFLOW;
		}
		index = free_mapping_index_locked(catalog);
		if (index < 0) {
			catalog_unlock(catalog);
			return index;
		}
		ret = copy_mapping(
			&candidate, mapping,
			catalog->next_mapping_id);
		if (ret != 0) {
			catalog_unlock(catalog);
			return ret;
		}
		catalog->next_mapping_id++;
	} else {
		index = mapping_index_by_id_locked(
			catalog, mapping->mapping_id);
		if (index < 0) {
			catalog_unlock(catalog);
			return index;
		}
		if (identity_index >= 0 &&
		    identity_index != index) {
			catalog_unlock(catalog);
			return -EEXIST;
		}
		if (!mapping_identity_equal(
			    &catalog->mappings[index], mapping)) {
			catalog_unlock(catalog);
			return -EACCES;
		}
		if (mapping_content_equal(
			    &catalog->mappings[index], mapping)) {
			catalog_unlock(catalog);
			return -EALREADY;
		}
		if (mapping->policy_epoch <=
		    catalog->mappings[index].policy_epoch) {
			catalog_unlock(catalog);
			return -ESTALE;
		}
		ret = copy_mapping(
			&candidate, mapping, mapping->mapping_id);
		if (ret != 0) {
			catalog_unlock(catalog);
			return ret;
		}
	}
	if (!mapping_shape_valid(&candidate)) {
		catalog_unlock(catalog);
		return -EBADMSG;
	}
	catalog->mappings[index] = candidate;
	catalog->generation++;
	catalog_unlock(catalog);
	return 0;
}

int pqcp_sovereign_control_mapping_remove(
	struct pqcp_sovereign_control_catalog *catalog,
	uint32_t mapping_id)
{
	int index;
	int ret;

	if (mapping_id == 0U) {
		return -EINVAL;
	}
	ret = catalog_lock(catalog);
	if (ret != 0) {
		return ret;
	}
	index = mapping_index_by_id_locked(catalog, mapping_id);
	if (index < 0) {
		catalog_unlock(catalog);
		return index;
	}
	if (catalog->generation == UINT64_MAX) {
		catalog_unlock(catalog);
		return -EOVERFLOW;
	}
	memset(&catalog->mappings[index], 0,
	       sizeof(catalog->mappings[index]));
	catalog->generation++;
	catalog_unlock(catalog);
	return 0;
}

int pqcp_sovereign_control_resolve(
	struct pqcp_sovereign_control_catalog *catalog,
	const char *internal_control,
	const char *framework,
	struct pqcp_sovereign_control_mapping **mapping)
{
	int index;
	int ret;

	if (!pqcp_sovereign_internal_text_valid(
		    internal_control, PQCP_SOVEREIGN_CONTROL_MAX_CHARS) ||
	    !pqcp_sovereign_internal_text_valid(
		    framework, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    mapping == NULL) {
		return -EINVAL;
	}
	*mapping = NULL;
	ret = catalog_lock(catalog);
	if (ret != 0) {
		return ret;
	}
	index = mapping_index_by_scope_locked(
		catalog, internal_control, framework);
	if (index < 0) {
		catalog_unlock(catalog);
		return index;
	}
	if (!catalog->mappings[index].enabled) {
		catalog_unlock(catalog);
		return -EACCES;
	}
	*mapping = &catalog->mappings[index];
	catalog_unlock(catalog);
	return 0;
}

int pqcp_sovereign_control_catalog_audit(
	struct pqcp_sovereign_control_catalog *catalog)
{
	uint32_t maximum_id = 0U;
	size_t left;
	size_t right;
	int ret;

	ret = catalog_lock(catalog);
	if (ret != 0) {
		return ret;
	}
	if (catalog->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    catalog->mappings == NULL ||
	    catalog->capacity == 0U ||
	    catalog->next_mapping_id == 0U ||
	    catalog->generation == 0U) {
		catalog_unlock(catalog);
		return -EBADMSG;
	}
	for (left = 0U; left < catalog->capacity; ++left) {
		const struct pqcp_sovereign_control_mapping *mapping =
			&catalog->mappings[left];

		if (mapping->mapping_id == 0U) {
			if (mapping->schema_version != 0U ||
			    mapping->internal_control[0] != '\0' ||
			    mapping->framework[0] != '\0' ||
			    mapping->external_control[0] != '\0' ||
			    mapping->evidence_type[0] != '\0' ||
			    mapping->policy_epoch != 0U ||
			    mapping->weight_basis_points != 0U ||
			    mapping->mandatory || mapping->enabled) {
				catalog_unlock(catalog);
				return -EBADMSG;
			}
			continue;
		}
		if (!mapping_shape_valid(mapping)) {
			catalog_unlock(catalog);
			return -EBADMSG;
		}
		if (mapping->mapping_id > maximum_id) {
			maximum_id = mapping->mapping_id;
		}
		for (right = left + 1U;
		     right < catalog->capacity; ++right) {
			const struct pqcp_sovereign_control_mapping *peer =
				&catalog->mappings[right];

			if (peer->mapping_id == 0U) {
				continue;
			}
			if (peer->mapping_id == mapping->mapping_id ||
			    mapping_identity_equal(peer, mapping)) {
				catalog_unlock(catalog);
				return -EBADMSG;
			}
		}
	}
	if (maximum_id != 0U &&
	    catalog->next_mapping_id <= maximum_id) {
		catalog_unlock(catalog);
		return -EBADMSG;
	}
	catalog_unlock(catalog);
	return 0;
}
