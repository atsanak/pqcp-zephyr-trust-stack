/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free regulatory evidence packaging with canonical digest chains.
 */

#include <pqcp_zephyr/sovereign_runtime.h>

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"

#define EVIDENCE_PACKAGE_DOMAIN "PQCP-SOVEREIGN-EVIDENCE-PACKAGE-V1"
#define EVIDENCE_REFERENCE_DOMAIN "PQCP-SOVEREIGN-EVIDENCE-REFERENCE-V1"
#define EVIDENCE_FINAL_DOMAIN "PQCP-SOVEREIGN-EVIDENCE-FINAL-V1"
#define EVIDENCE_PACKAGE_NUMERIC_BYTES 72U
#define EVIDENCE_REFERENCE_NUMERIC_BYTES 25U

static bool bytes_all_zero(const void *value, size_t length)
{
	const uint8_t *bytes = value;
	uint8_t aggregate = 0U;
	size_t index;

	if (value == NULL) {
		return false;
	}
	for (index = 0U; index < length; ++index) {
		aggregate |= bytes[index];
	}
	return aggregate == 0U;
}

static bool digest_all_zero(
	const uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	return digest == NULL ||
	       bytes_all_zero(digest, PQCP_SOVEREIGN_DIGEST_BYTES);
}

static size_t bounded_text_length(const char *text, size_t capacity)
{
	size_t length;

	if (text == NULL || capacity == 0U) {
		return SIZE_MAX;
	}
	for (length = 0U; length < capacity; ++length) {
		if (text[length] == '\0') {
			return length;
		}
	}
	return SIZE_MAX;
}

static bool canonical_token_character(char character)
{
	return (character >= 'a' && character <= 'z') ||
	       (character >= 'A' && character <= 'Z') ||
	       (character >= '0' && character <= '9') ||
	       character == '-' || character == '_' || character == '.';
}

static bool canonical_token_valid(const char *text, size_t capacity)
{
	size_t length = bounded_text_length(text, capacity);
	size_t index;

	if (length == 0U || length == SIZE_MAX) {
		return false;
	}
	for (index = 0U; index < length; ++index) {
		if (!canonical_token_character(text[index])) {
			return false;
		}
	}
	return true;
}

static bool canonical_metadata_valid(const char *text, size_t capacity)
{
	size_t length = bounded_text_length(text, capacity);
	size_t index;

	if (length == 0U || length == SIZE_MAX) {
		return false;
	}
	for (index = 0U; index < length; ++index) {
		unsigned char character = (unsigned char)text[index];

		if (character <= 0x20U || character >= 0x7fU ||
		    character == '\\') {
			return false;
		}
	}
	return true;
}

static bool scoped_subject_valid(const char *subject, size_t capacity)
{
	size_t length = bounded_text_length(subject, capacity);
	size_t separator = SIZE_MAX;
	size_t index;

	if (length < 3U || length == SIZE_MAX) {
		return false;
	}
	for (index = 0U; index < length; ++index) {
		if (subject[index] == '/' || subject[index] == ':') {
			if (separator != SIZE_MAX) {
				return false;
			}
			separator = index;
			continue;
		}
		if (!canonical_token_character(subject[index])) {
			return false;
		}
	}
	return separator != SIZE_MAX && separator != 0U &&
	       separator + 1U < length;
}

static int copy_text(char *destination, size_t capacity,
		     const char *source)
{
	size_t length = bounded_text_length(source, capacity);

	if (destination == NULL || length == 0U ||
	    length == SIZE_MAX) {
		return -EINVAL;
	}
	memcpy(destination, source, length + 1U);
	return 0;
}

static void write_u32(uint8_t output[4], uint32_t value)
{
	output[0] = (uint8_t)(value >> 24);
	output[1] = (uint8_t)(value >> 16);
	output[2] = (uint8_t)(value >> 8);
	output[3] = (uint8_t)value;
}

static void write_u64(uint8_t output[8], uint64_t value)
{
	output[0] = (uint8_t)(value >> 56);
	output[1] = (uint8_t)(value >> 48);
	output[2] = (uint8_t)(value >> 40);
	output[3] = (uint8_t)(value >> 32);
	output[4] = (uint8_t)(value >> 24);
	output[5] = (uint8_t)(value >> 16);
	output[6] = (uint8_t)(value >> 8);
	output[7] = (uint8_t)value;
}

static int packager_lock(struct pqcp_sovereign_evidence_packager *packager)
{
	int ret;

	if (packager == NULL || !packager->initialized) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&packager->lock, K_FOREVER);
	return ret == 0 ? 0 : -EDEADLK;
}

static void packager_unlock(
	struct pqcp_sovereign_evidence_packager *packager)
{
	if (packager != NULL) {
		(void)k_mutex_unlock(&packager->lock);
	}
}

static struct pqcp_sovereign_evidence_package *find_package_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id)
{
	size_t index;

	for (index = 0U; index < packager->package_capacity; ++index) {
		if (packager->packages[index].occupied &&
		    packager->packages[index].package_id == package_id) {
			return &packager->packages[index];
		}
	}
	return NULL;
}

static struct pqcp_sovereign_evidence_package *free_package_locked(
	const struct pqcp_sovereign_evidence_packager *packager)
{
	size_t index;

	for (index = 0U; index < packager->package_capacity; ++index) {
		if (!packager->packages[index].occupied) {
			return &packager->packages[index];
		}
	}
	return NULL;
}

static struct pqcp_sovereign_evidence_reference *free_reference_locked(
	const struct pqcp_sovereign_evidence_packager *packager)
{
	size_t index;

	for (index = 0U; index < packager->reference_capacity; ++index) {
		if (!packager->references[index].occupied) {
			return &packager->references[index];
		}
	}
	return NULL;
}

static const struct pqcp_sovereign_evidence_package *
predecessor_package_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id)
{
	const struct pqcp_sovereign_evidence_package *predecessor = NULL;
	size_t index;

	for (index = 0U; index < packager->package_capacity; ++index) {
		const struct pqcp_sovereign_evidence_package *candidate =
			&packager->packages[index];

		if (!candidate->occupied ||
		    candidate->package_id >= package_id) {
			continue;
		}
		if (predecessor == NULL ||
		    candidate->package_id > predecessor->package_id) {
			predecessor = candidate;
		}
	}
	return predecessor;
}

static bool lower_package_unsealed_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id)
{
	size_t index;

	for (index = 0U; index < packager->package_capacity; ++index) {
		const struct pqcp_sovereign_evidence_package *candidate =
			&packager->packages[index];

		if (candidate->occupied &&
		    candidate->package_id < package_id &&
		    !candidate->sealed) {
			return true;
		}
	}
	return false;
}

static bool duplicate_package_tuple_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	const char *subject_id,
	const char *framework,
	uint64_t period_started_ms,
	uint64_t period_ended_ms,
	uint64_t policy_epoch)
{
	size_t index;

	for (index = 0U; index < packager->package_capacity; ++index) {
		const struct pqcp_sovereign_evidence_package *package =
			&packager->packages[index];

		if (!package->occupied) {
			continue;
		}
		if (strcmp(package->subject_id, subject_id) == 0 &&
		    strcmp(package->framework, framework) == 0 &&
		    package->period_started_ms == period_started_ms &&
		    package->period_ended_ms == period_ended_ms &&
		    package->policy_epoch == policy_epoch) {
			return true;
		}
	}
	return false;
}

static bool duplicate_reference_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id,
	const char *evidence_id)
{
	size_t index;

	for (index = 0U; index < packager->reference_capacity; ++index) {
		const struct pqcp_sovereign_evidence_reference *reference =
			&packager->references[index];

		if (reference->occupied &&
		    reference->package_id == package_id &&
		    strcmp(reference->evidence_id, evidence_id) == 0) {
			return true;
		}
	}
	return false;
}

static uint32_t reference_count_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id,
	uint32_t *verified_count)
{
	uint32_t count = 0U;
	uint32_t verified = 0U;
	size_t index;

	for (index = 0U; index < packager->reference_capacity; ++index) {
		const struct pqcp_sovereign_evidence_reference *reference =
			&packager->references[index];

		if (!reference->occupied ||
		    reference->package_id != package_id) {
			continue;
		}
		if (count != UINT32_MAX) {
			count++;
		}
		if (reference->verified && verified != UINT32_MAX) {
			verified++;
		}
	}
	if (verified_count != NULL) {
		*verified_count = verified;
	}
	return count;
}

static uint32_t distinct_verified_controls_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id)
{
	uint32_t distinct = 0U;
	size_t index;
	size_t previous;

	for (index = 0U; index < packager->reference_capacity; ++index) {
		const struct pqcp_sovereign_evidence_reference *reference =
			&packager->references[index];
		bool seen = false;

		if (!reference->occupied ||
		    reference->package_id != package_id ||
		    !reference->verified) {
			continue;
		}
		for (previous = 0U; previous < index; ++previous) {
			const struct pqcp_sovereign_evidence_reference *other =
				&packager->references[previous];

			if (other->occupied &&
			    other->package_id == package_id &&
			    other->verified &&
			    strcmp(other->control_id,
				   reference->control_id) == 0) {
				seen = true;
				break;
			}
		}
		if (!seen && distinct != UINT32_MAX) {
			distinct++;
		}
	}
	return distinct;
}

static const struct pqcp_sovereign_evidence_reference *
next_canonical_reference_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id,
	const char *after_evidence_id)
{
	const struct pqcp_sovereign_evidence_reference *selected = NULL;
	size_t index;

	for (index = 0U; index < packager->reference_capacity; ++index) {
		const struct pqcp_sovereign_evidence_reference *candidate =
			&packager->references[index];

		if (!candidate->occupied ||
		    candidate->package_id != package_id ||
		    (after_evidence_id != NULL &&
		     strcmp(candidate->evidence_id,
			    after_evidence_id) <= 0)) {
			continue;
		}
		if (selected == NULL ||
		    strcmp(candidate->evidence_id,
			   selected->evidence_id) < 0) {
			selected = candidate;
		}
	}
	return selected;
}

static void encode_package_numeric(
	const struct pqcp_sovereign_evidence_package *package,
	uint8_t output[EVIDENCE_PACKAGE_NUMERIC_BYTES])
{
	size_t offset = 0U;

	write_u32(&output[offset], package->schema_version);
	offset += 4U;
	write_u64(&output[offset], package->package_id);
	offset += 8U;
	write_u64(&output[offset], package->period_started_ms);
	offset += 8U;
	write_u64(&output[offset], package->period_ended_ms);
	offset += 8U;
	write_u64(&output[offset], package->generated_at_ms);
	offset += 8U;
	write_u64(&output[offset], package->policy_epoch);
	offset += 8U;
	write_u32(&output[offset], package->evidence_count);
	offset += 4U;
	write_u32(&output[offset], package->verified_count);
	offset += 4U;
	write_u32(&output[offset], package->mandatory_control_count);
	offset += 4U;
	write_u32(&output[offset], package->satisfied_control_count);
	offset += 4U;
	write_u32(&output[offset], package->score_basis_points);
	offset += 4U;
	write_u32(&output[offset], package->sealed ? 1U : 0U);
	offset += 4U;
	write_u32(&output[offset], package->occupied ? 1U : 0U);
}

static void encode_reference_numeric(
	const struct pqcp_sovereign_evidence_reference *reference,
	uint8_t output[EVIDENCE_REFERENCE_NUMERIC_BYTES])
{
	size_t offset = 0U;

	write_u32(&output[offset], reference->schema_version);
	offset += 4U;
	write_u64(&output[offset], reference->package_id);
	offset += 8U;
	write_u64(&output[offset], reference->observed_at_ms);
	offset += 8U;
	write_u32(&output[offset], reference->verified ? 1U : 0U);
	offset += 4U;
	output[offset] = reference->occupied ? 1U : 0U;
}

static int compute_package_digest_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	const struct pqcp_sovereign_evidence_package *package,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	const struct pqcp_sovereign_evidence_package *predecessor;
	const struct pqcp_sovereign_evidence_reference *reference;
	const char *last_evidence_id = NULL;
	uint8_t previous_digest[PQCP_SOVEREIGN_DIGEST_BYTES] = { 0 };
	uint8_t accumulator[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t next_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint8_t package_numeric[EVIDENCE_PACKAGE_NUMERIC_BYTES];
	uint8_t reference_numeric[EVIDENCE_REFERENCE_NUMERIC_BYTES];
	uint8_t final_count[4];
	const uint8_t *parts[8];
	size_t lengths[8];
	size_t reference_iterations = 0U;
	int ret;

	if (packager == NULL || package == NULL || digest == NULL ||
	    !package->sealed || !package->occupied) {
		return -EINVAL;
	}
	predecessor = predecessor_package_locked(
		packager, package->package_id);
	if (predecessor != NULL) {
		if (!predecessor->sealed ||
		    digest_all_zero(predecessor->package_digest)) {
			return -EBADMSG;
		}
		memcpy(previous_digest, predecessor->package_digest,
		       sizeof(previous_digest));
	}
	encode_package_numeric(package, package_numeric);
	parts[0] = (const uint8_t *)EVIDENCE_PACKAGE_DOMAIN;
	lengths[0] = sizeof(EVIDENCE_PACKAGE_DOMAIN) - 1U;
	parts[1] = previous_digest;
	lengths[1] = sizeof(previous_digest);
	parts[2] = (const uint8_t *)package->subject_id;
	lengths[2] = bounded_text_length(
		package->subject_id, sizeof(package->subject_id));
	parts[3] = (const uint8_t *)package->framework;
	lengths[3] = bounded_text_length(
		package->framework, sizeof(package->framework));
	parts[4] = package_numeric;
	lengths[4] = sizeof(package_numeric);
	ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths, 5U, accumulator);
	if (ret != 0) {
		goto out;
	}
	while ((reference = next_canonical_reference_locked(
			packager, package->package_id,
			last_evidence_id)) != NULL) {
		if (reference_iterations >=
		    PQCP_SOVEREIGN_MAX_EVIDENCE_REFS) {
			ret = -E2BIG;
			goto out;
		}
		encode_reference_numeric(reference, reference_numeric);
		parts[0] = (const uint8_t *)EVIDENCE_REFERENCE_DOMAIN;
		lengths[0] = sizeof(EVIDENCE_REFERENCE_DOMAIN) - 1U;
		parts[1] = accumulator;
		lengths[1] = sizeof(accumulator);
		parts[2] = (const uint8_t *)reference->evidence_id;
		lengths[2] = bounded_text_length(
			reference->evidence_id,
			sizeof(reference->evidence_id));
		parts[3] = (const uint8_t *)reference->evidence_type;
		lengths[3] = bounded_text_length(
			reference->evidence_type,
			sizeof(reference->evidence_type));
		parts[4] = (const uint8_t *)reference->control_id;
		lengths[4] = bounded_text_length(
			reference->control_id,
			sizeof(reference->control_id));
		parts[5] = reference->evidence_digest;
		lengths[5] = sizeof(reference->evidence_digest);
		parts[6] = reference_numeric;
		lengths[6] = sizeof(reference_numeric);
		ret = pqcp_runtime_internal_sha256_parts(
			parts, lengths, 7U, next_digest);
		if (ret != 0) {
			goto out;
		}
		memcpy(accumulator, next_digest, sizeof(accumulator));
		last_evidence_id = reference->evidence_id;
		reference_iterations++;
	}
	if (reference_iterations != package->evidence_count) {
		ret = -EBADMSG;
		goto out;
	}
	write_u32(final_count, (uint32_t)reference_iterations);
	parts[0] = (const uint8_t *)EVIDENCE_FINAL_DOMAIN;
	lengths[0] = sizeof(EVIDENCE_FINAL_DOMAIN) - 1U;
	parts[1] = accumulator;
	lengths[1] = sizeof(accumulator);
	parts[2] = final_count;
	lengths[2] = sizeof(final_count);
	ret = pqcp_runtime_internal_sha256_parts(
		parts, lengths, 3U, digest);

out:
	pqcp_runtime_secure_zero(previous_digest,
				 sizeof(previous_digest));
	pqcp_runtime_secure_zero(accumulator, sizeof(accumulator));
	pqcp_runtime_secure_zero(next_digest, sizeof(next_digest));
	pqcp_runtime_secure_zero(package_numeric,
				 sizeof(package_numeric));
	pqcp_runtime_secure_zero(reference_numeric,
				 sizeof(reference_numeric));
	pqcp_runtime_secure_zero(final_count, sizeof(final_count));
	if (ret != 0) {
		pqcp_runtime_secure_zero(
			digest, PQCP_SOVEREIGN_DIGEST_BYTES);
	}
	return ret;
}

static bool reference_structurally_valid(
	const struct pqcp_sovereign_evidence_reference *reference,
	const struct pqcp_sovereign_evidence_package *package)
{
	return reference != NULL && package != NULL &&
	       reference->occupied &&
	       reference->schema_version == PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       reference->package_id == package->package_id &&
	       canonical_metadata_valid(
		       reference->evidence_id,
		       sizeof(reference->evidence_id)) &&
	       canonical_metadata_valid(
		       reference->evidence_type,
		       sizeof(reference->evidence_type)) &&
	       canonical_metadata_valid(
		       reference->control_id,
		       sizeof(reference->control_id)) &&
	       reference->observed_at_ms >= package->period_started_ms &&
	       reference->observed_at_ms <= package->period_ended_ms &&
	       !digest_all_zero(reference->evidence_digest);
}

static bool package_structurally_valid(
	const struct pqcp_sovereign_evidence_package *package)
{
	if (package == NULL || !package->occupied ||
	    package->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    package->package_id == 0U ||
	    !scoped_subject_valid(
		    package->subject_id, sizeof(package->subject_id)) ||
	    !canonical_token_valid(
		    package->framework, sizeof(package->framework)) ||
	    package->period_started_ms == 0U ||
	    package->period_ended_ms < package->period_started_ms ||
	    package->policy_epoch == 0U ||
	    package->mandatory_control_count == 0U ||
	    package->mandatory_control_count >
		    PQCP_SOVEREIGN_MAX_CONTROL_REFS ||
	    package->evidence_count >
		    PQCP_SOVEREIGN_MAX_EVIDENCE_REFS ||
	    package->verified_count > package->evidence_count ||
	    package->satisfied_control_count >
		    package->mandatory_control_count ||
	    package->score_basis_points > 10000U) {
		return false;
	}
	if (package->sealed) {
		if (package->generated_at_ms < package->period_ended_ms ||
		    digest_all_zero(package->package_digest)) {
			return false;
		}
	} else if (package->generated_at_ms != 0U ||
		   package->satisfied_control_count != 0U ||
		   package->score_basis_points != 0U ||
		   !digest_all_zero(package->package_digest)) {
		return false;
	}
	return true;
}

int pqcp_sovereign_evidence_packager_init(
	struct pqcp_sovereign_evidence_packager *packager,
	struct pqcp_sovereign_evidence_package *packages,
	size_t package_capacity,
	struct pqcp_sovereign_evidence_reference *references,
	size_t reference_capacity)
{
	if (packager == NULL || packages == NULL ||
	    references == NULL || package_capacity == 0U ||
	    reference_capacity == 0U ||
	    package_capacity >
		    SIZE_MAX / sizeof(*packages) ||
	    reference_capacity >
		    SIZE_MAX / sizeof(*references)) {
		return -EINVAL;
	}
	memset(packager, 0, sizeof(*packager));
	memset(packages, 0,
	       package_capacity * sizeof(*packages));
	memset(references, 0,
	       reference_capacity * sizeof(*references));
	packager->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	packager->packages = packages;
	packager->package_capacity = package_capacity;
	packager->references = references;
	packager->reference_capacity = reference_capacity;
	packager->next_package_id = 1U;
	k_mutex_init(&packager->lock);
	packager->initialized = true;
	return 0;
}

int pqcp_sovereign_evidence_package_open(
	struct pqcp_sovereign_evidence_packager *packager,
	const char *subject_id,
	const char *framework,
	uint64_t period_started_ms,
	uint64_t period_ended_ms,
	uint64_t policy_epoch,
	uint32_t mandatory_control_count,
	uint64_t now_ms,
	struct pqcp_sovereign_evidence_package **package)
{
	struct pqcp_sovereign_evidence_package staged;
	struct pqcp_sovereign_evidence_package *slot;
	uint64_t package_id;
	int ret;

	if (packager == NULL || !packager->initialized ||
	    package == NULL ||
	    !scoped_subject_valid(
		    subject_id, PQCP_SOVEREIGN_SUBJECT_MAX_CHARS) ||
	    !canonical_token_valid(
		    framework, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    period_started_ms == 0U ||
	    period_ended_ms < period_started_ms ||
	    period_ended_ms > now_ms || policy_epoch == 0U ||
	    mandatory_control_count == 0U ||
	    mandatory_control_count >
		    PQCP_SOVEREIGN_MAX_CONTROL_REFS ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	*package = NULL;
	ret = packager_lock(packager);
	if (ret != 0) {
		return ret;
	}
	if (packager->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    packager->packages == NULL ||
	    packager->references == NULL ||
	    packager->package_capacity == 0U ||
	    packager->reference_capacity == 0U) {
		ret = -EBADMSG;
		goto out;
	}
	if (duplicate_package_tuple_locked(
		    packager, subject_id, framework,
		    period_started_ms, period_ended_ms,
		    policy_epoch)) {
		ret = -EALREADY;
		goto out;
	}
	slot = free_package_locked(packager);
	if (slot == NULL) {
		ret = -ENOSPC;
		goto out;
	}
	if (packager->next_package_id == 0U ||
	    packager->next_package_id == UINT64_MAX) {
		ret = -EOVERFLOW;
		goto out;
	}
	package_id = packager->next_package_id;
	memset(&staged, 0, sizeof(staged));
	staged.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.package_id = package_id;
	staged.period_started_ms = period_started_ms;
	staged.period_ended_ms = period_ended_ms;
	staged.policy_epoch = policy_epoch;
	staged.mandatory_control_count = mandatory_control_count;
	staged.occupied = true;
	ret = copy_text(staged.subject_id,
			sizeof(staged.subject_id), subject_id);
	if (ret == 0) {
		ret = copy_text(staged.framework,
				sizeof(staged.framework), framework);
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(&staged, sizeof(staged));
		goto out;
	}
	*slot = staged;
	packager->next_package_id = package_id + 1U;
	*package = slot;
	pqcp_runtime_secure_zero(&staged, sizeof(staged));

out:
	packager_unlock(packager);
	return ret;
}

int pqcp_sovereign_evidence_package_add(
	struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id,
	const char *evidence_id,
	const char *evidence_type,
	const char *control_id,
	uint64_t observed_at_ms,
	const uint8_t evidence_digest[PQCP_SOVEREIGN_DIGEST_BYTES],
	bool verified)
{
	struct pqcp_sovereign_evidence_reference staged;
	struct pqcp_sovereign_evidence_reference *slot;
	struct pqcp_sovereign_evidence_package *package;
	int ret;

	if (packager == NULL || !packager->initialized ||
	    package_id == 0U ||
	    !canonical_metadata_valid(
		    evidence_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !canonical_metadata_valid(
		    evidence_type, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    !canonical_metadata_valid(
		    control_id, PQCP_SOVEREIGN_CONTROL_MAX_CHARS) ||
	    observed_at_ms == 0U ||
	    digest_all_zero(evidence_digest)) {
		return -EINVAL;
	}
	ret = packager_lock(packager);
	if (ret != 0) {
		return ret;
	}
	package = find_package_locked(packager, package_id);
	if (package == NULL) {
		ret = -ENOENT;
		goto out;
	}
	if (package->sealed) {
		ret = -EPERM;
		goto out;
	}
	if (observed_at_ms < package->period_started_ms ||
	    observed_at_ms > package->period_ended_ms) {
		ret = -ERANGE;
		goto out;
	}
	if (package->evidence_count >=
		    PQCP_SOVEREIGN_MAX_EVIDENCE_REFS ||
	    package->evidence_count == UINT32_MAX ||
	    (verified && package->verified_count == UINT32_MAX)) {
		ret = -E2BIG;
		goto out;
	}
	if (duplicate_reference_locked(
		    packager, package_id, evidence_id)) {
		ret = -EALREADY;
		goto out;
	}
	slot = free_reference_locked(packager);
	if (slot == NULL) {
		ret = -ENOSPC;
		goto out;
	}
	memset(&staged, 0, sizeof(staged));
	staged.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.package_id = package_id;
	staged.observed_at_ms = observed_at_ms;
	memcpy(staged.evidence_digest, evidence_digest,
	       sizeof(staged.evidence_digest));
	staged.verified = verified;
	staged.occupied = true;
	ret = copy_text(staged.evidence_id,
			sizeof(staged.evidence_id), evidence_id);
	if (ret == 0) {
		ret = copy_text(staged.evidence_type,
				sizeof(staged.evidence_type),
				evidence_type);
	}
	if (ret == 0) {
		ret = copy_text(staged.control_id,
				sizeof(staged.control_id), control_id);
	}
	if (ret != 0) {
		pqcp_runtime_secure_zero(&staged, sizeof(staged));
		goto out;
	}
	*slot = staged;
	package->evidence_count++;
	if (verified) {
		package->verified_count++;
	}
	pqcp_runtime_secure_zero(&staged, sizeof(staged));

out:
	packager_unlock(packager);
	return ret;
}

int pqcp_sovereign_evidence_package_seal(
	struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id,
	uint32_t satisfied_control_count,
	uint64_t now_ms)
{
	struct pqcp_sovereign_evidence_package staged;
	struct pqcp_sovereign_evidence_package *package;
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint32_t actual_count;
	uint32_t actual_verified;
	uint32_t distinct_verified;
	uint64_t scaled_score;
	int ret;

	if (packager == NULL || !packager->initialized ||
	    package_id == 0U || now_ms == 0U) {
		return -EINVAL;
	}
	ret = packager_lock(packager);
	if (ret != 0) {
		return ret;
	}
	package = find_package_locked(packager, package_id);
	if (package == NULL) {
		ret = -ENOENT;
		goto out;
	}
	if (package->sealed) {
		ret = -EALREADY;
		goto out;
	}
	if (now_ms < package->period_ended_ms) {
		ret = -ETIME;
		goto out;
	}
	if (lower_package_unsealed_locked(packager, package_id)) {
		ret = -EAGAIN;
		goto out;
	}
	actual_count = reference_count_locked(
		packager, package_id, &actual_verified);
	if (actual_count == 0U ||
	    actual_count != package->evidence_count ||
	    actual_verified != package->verified_count) {
		ret = -EBADMSG;
		goto out;
	}
	distinct_verified = distinct_verified_controls_locked(
		packager, package_id);
	if (satisfied_control_count >
		    package->mandatory_control_count ||
	    satisfied_control_count > distinct_verified) {
		ret = -ERANGE;
		goto out;
	}
	staged = *package;
	staged.generated_at_ms = now_ms;
	staged.satisfied_control_count = satisfied_control_count;
	scaled_score =
		(uint64_t)satisfied_control_count * 10000U;
	staged.score_basis_points =
		(uint32_t)(scaled_score /
			   staged.mandatory_control_count);
	staged.sealed = true;
	ret = compute_package_digest_locked(
		packager, &staged, digest);
	if (ret != 0) {
		pqcp_runtime_secure_zero(&staged, sizeof(staged));
		goto out;
	}
	memcpy(staged.package_digest, digest,
	       sizeof(staged.package_digest));
	*package = staged;
	if (packager->sealed_count != UINT64_MAX) {
		packager->sealed_count++;
	} else {
		ret = -EOVERFLOW;
		pqcp_runtime_secure_zero(package->package_digest,
					 sizeof(package->package_digest));
		package->generated_at_ms = 0U;
		package->satisfied_control_count = 0U;
		package->score_basis_points = 0U;
		package->sealed = false;
	}
	pqcp_runtime_secure_zero(&staged, sizeof(staged));

out:
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	packager_unlock(packager);
	return ret;
}

int pqcp_sovereign_evidence_package_find(
	struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id,
	struct pqcp_sovereign_evidence_package **package)
{
	int ret;

	if (packager == NULL || !packager->initialized ||
	    package_id == 0U || package == NULL) {
		return -EINVAL;
	}
	*package = NULL;
	ret = packager_lock(packager);
	if (ret != 0) {
		return ret;
	}
	*package = find_package_locked(packager, package_id);
	ret = *package == NULL ? -ENOENT : 0;
	packager_unlock(packager);
	return ret;
}

static int audit_reference_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	const struct pqcp_sovereign_evidence_reference *reference,
	size_t reference_index)
{
	const struct pqcp_sovereign_evidence_package *package;
	size_t other;

	if (!reference->occupied) {
		return bytes_all_zero(reference, sizeof(*reference)) ?
			0 : -EBADMSG;
	}
	package = find_package_locked(
		packager, reference->package_id);
	if (!reference_structurally_valid(reference, package)) {
		return -EBADMSG;
	}
	for (other = reference_index + 1U;
	     other < packager->reference_capacity; ++other) {
		const struct pqcp_sovereign_evidence_reference *candidate =
			&packager->references[other];

		if (candidate->occupied &&
		    candidate->package_id == reference->package_id &&
		    strcmp(candidate->evidence_id,
			   reference->evidence_id) == 0) {
			return -EEXIST;
		}
	}
	return 0;
}

static int audit_package_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	const struct pqcp_sovereign_evidence_package *package,
	size_t package_index)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	uint32_t actual_count;
	uint32_t actual_verified;
	uint32_t distinct_verified;
	uint32_t expected_score;
	size_t other;
	int ret = 0;

	if (!package->occupied) {
		return bytes_all_zero(package, sizeof(*package)) ?
			0 : -EBADMSG;
	}
	if (!package_structurally_valid(package)) {
		return -EBADMSG;
	}
	for (other = package_index + 1U;
	     other < packager->package_capacity; ++other) {
		const struct pqcp_sovereign_evidence_package *candidate =
			&packager->packages[other];

		if (candidate->occupied &&
		    candidate->package_id == package->package_id) {
			return -EEXIST;
		}
		if (candidate->occupied &&
		    strcmp(candidate->subject_id,
			   package->subject_id) == 0 &&
		    strcmp(candidate->framework,
			   package->framework) == 0 &&
		    candidate->period_started_ms ==
			    package->period_started_ms &&
		    candidate->period_ended_ms ==
			    package->period_ended_ms &&
		    candidate->policy_epoch ==
			    package->policy_epoch) {
			return -EALREADY;
		}
	}
	actual_count = reference_count_locked(
		packager, package->package_id,
		&actual_verified);
	if (actual_count != package->evidence_count ||
	    actual_verified != package->verified_count) {
		return -EBADMSG;
	}
	if (!package->sealed) {
		return 0;
	}
	distinct_verified = distinct_verified_controls_locked(
		packager, package->package_id);
	if (package->evidence_count == 0U ||
	    package->satisfied_control_count >
		    distinct_verified) {
		return -EBADMSG;
	}
	expected_score = (uint32_t)(
		((uint64_t)package->satisfied_control_count *
		 10000U) / package->mandatory_control_count);
	if (package->score_basis_points != expected_score) {
		return -EBADMSG;
	}
	ret = compute_package_digest_locked(
		packager, package, digest);
	if (ret == 0 &&
	    memcmp(digest, package->package_digest,
		   sizeof(digest)) != 0) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return ret;
}

int pqcp_sovereign_evidence_packager_audit(
	struct pqcp_sovereign_evidence_packager *packager)
{
	uint64_t sealed_count = 0U;
	uint64_t maximum_package_id = 0U;
	uint64_t occupied_packages = 0U;
	size_t index;
	int ret;

	if (packager == NULL || !packager->initialized ||
	    packager->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    packager->packages == NULL ||
	    packager->references == NULL ||
	    packager->package_capacity == 0U ||
	    packager->reference_capacity == 0U ||
	    packager->next_package_id == 0U) {
		return -EINVAL;
	}
	ret = packager_lock(packager);
	if (ret != 0) {
		return ret;
	}
	for (index = 0U; index < packager->reference_capacity;
	     ++index) {
		ret = audit_reference_locked(
			packager, &packager->references[index], index);
		if (ret != 0) {
			goto out;
		}
	}
	for (index = 0U; index < packager->package_capacity;
	     ++index) {
		const struct pqcp_sovereign_evidence_package *package =
			&packager->packages[index];

		ret = audit_package_locked(packager, package, index);
		if (ret != 0) {
			goto out;
		}
		if (!package->occupied) {
			continue;
		}
		occupied_packages++;
		if (package->sealed) {
			sealed_count++;
		}
		if (package->package_id > maximum_package_id) {
			maximum_package_id = package->package_id;
		}
	}
	if (sealed_count != packager->sealed_count ||
	    occupied_packages != maximum_package_id ||
	    packager->next_package_id != maximum_package_id + 1U) {
		ret = -EBADMSG;
		goto out;
	}
	ret = 0;

out:
	packager_unlock(packager);
	return ret;
}
