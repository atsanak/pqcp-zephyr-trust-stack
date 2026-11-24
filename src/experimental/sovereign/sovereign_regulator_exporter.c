/*
 * SPDX-License-Identifier: MIT
 *
 * Tenant-scoped, exact-acknowledgement regulatory evidence export cursors.
 */

#include <pqcp_zephyr/sovereign_runtime.h>

#include <errno.h>
#include <limits.h>
#include <string.h>

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

static bool scoped_identity_valid(const char *identity, size_t capacity)
{
	size_t length = bounded_text_length(identity, capacity);
	size_t separator = SIZE_MAX;
	size_t index;

	if (length < 3U || length == SIZE_MAX) {
		return false;
	}
	for (index = 0U; index < length; ++index) {
		if (identity[index] == '/' || identity[index] == ':') {
			if (separator != SIZE_MAX) {
				return false;
			}
			separator = index;
			continue;
		}
		if (!canonical_token_character(identity[index])) {
			return false;
		}
	}
	return separator != SIZE_MAX && separator != 0U &&
	       separator + 1U < length;
}

static size_t scope_length(const char *identity, size_t capacity)
{
	size_t length = bounded_text_length(identity, capacity);
	size_t index;

	if (length == SIZE_MAX) {
		return SIZE_MAX;
	}
	for (index = 0U; index < length; ++index) {
		if (identity[index] == '/' || identity[index] == ':') {
			return index;
		}
	}
	return SIZE_MAX;
}

static bool same_tenant_scope(const char *left, size_t left_capacity,
			      const char *right, size_t right_capacity)
{
	size_t left_length = scope_length(left, left_capacity);
	size_t right_length = scope_length(right, right_capacity);

	return left_length != SIZE_MAX &&
	       right_length != SIZE_MAX &&
	       left_length == right_length &&
	       memcmp(left, right, left_length) == 0;
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

static bool digest_all_zero(
	const uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	return digest == NULL ||
	       bytes_all_zero(digest, PQCP_SOVEREIGN_DIGEST_BYTES);
}

static int exporter_lock(
	struct pqcp_sovereign_regulator_exporter *exporter)
{
	int ret;

	if (exporter == NULL || !exporter->initialized) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&exporter->lock, K_FOREVER);
	return ret == 0 ? 0 : -EDEADLK;
}

static void exporter_unlock(
	struct pqcp_sovereign_regulator_exporter *exporter)
{
	if (exporter != NULL) {
		(void)k_mutex_unlock(&exporter->lock);
	}
}

static int packager_lock(
	struct pqcp_sovereign_evidence_packager *packager)
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

static struct pqcp_sovereign_export_cursor *find_cursor_locked(
	const struct pqcp_sovereign_regulator_exporter *exporter,
	uint64_t cursor_id)
{
	size_t index;

	for (index = 0U; index < exporter->capacity; ++index) {
		if (exporter->cursors[index].occupied &&
		    exporter->cursors[index].cursor_id == cursor_id) {
			return &exporter->cursors[index];
		}
	}
	return NULL;
}

static struct pqcp_sovereign_export_cursor *free_cursor_locked(
	const struct pqcp_sovereign_regulator_exporter *exporter)
{
	size_t index;

	for (index = 0U; index < exporter->capacity; ++index) {
		if (!exporter->cursors[index].occupied) {
			return &exporter->cursors[index];
		}
	}
	return NULL;
}

static bool active_cursor_alias_locked(
	const struct pqcp_sovereign_regulator_exporter *exporter,
	const char *consumer_id,
	const char *framework)
{
	size_t index;

	for (index = 0U; index < exporter->capacity; ++index) {
		const struct pqcp_sovereign_export_cursor *cursor =
			&exporter->cursors[index];

		if (!cursor->occupied ||
		    cursor->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
			continue;
		}
		if (strcmp(cursor->consumer_id, consumer_id) == 0 &&
		    strcmp(cursor->framework, framework) == 0) {
			return true;
		}
	}
	return false;
}

static bool cursor_has_outstanding(
	const struct pqcp_sovereign_export_cursor *cursor)
{
	if (cursor == NULL ||
	    cursor->acknowledged_package_id == UINT64_MAX) {
		return false;
	}
	return cursor->next_package_id >
	       cursor->acknowledged_package_id + 1U;
}

static bool cursor_sequence_valid(
	const struct pqcp_sovereign_export_cursor *cursor)
{
	uint64_t base;

	if (cursor == NULL ||
	    cursor->next_package_id == 0U ||
	    cursor->acknowledged_package_id == UINT64_MAX) {
		return false;
	}
	base = cursor->acknowledged_package_id + 1U;
	return cursor->next_package_id == base ||
	       (base != UINT64_MAX &&
		cursor->next_package_id == base + 1U);
}

static bool cursor_structurally_valid(
	const struct pqcp_sovereign_export_cursor *cursor)
{
	if (cursor == NULL || !cursor->occupied ||
	    cursor->schema_version != PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    cursor->cursor_id == 0U ||
	    !scoped_identity_valid(
		    cursor->consumer_id,
		    sizeof(cursor->consumer_id)) ||
	    !canonical_token_valid(
		    cursor->framework,
		    sizeof(cursor->framework)) ||
	    cursor->opened_at_ms == 0U ||
	    cursor->expires_at_ms <= cursor->opened_at_ms ||
	    cursor->policy_epoch == 0U ||
	    !cursor_sequence_valid(cursor)) {
		return false;
	}
	if (cursor->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
	    cursor->state != PQCP_SOVEREIGN_LIFECYCLE_RETIRED &&
	    cursor->state != PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
		return false;
	}
	if (cursor->state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
	    cursor->maximum_batch == 0U &&
	    !cursor_has_outstanding(cursor)) {
		return false;
	}
	return true;
}

static const struct pqcp_sovereign_evidence_package *
find_exact_package_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	uint64_t package_id)
{
	size_t index;

	for (index = 0U; index < packager->package_capacity; ++index) {
		const struct pqcp_sovereign_evidence_package *package =
			&packager->packages[index];

		if (package->occupied &&
		    package->package_id == package_id) {
			return package;
		}
	}
	return NULL;
}

static const struct pqcp_sovereign_evidence_package *
find_next_scoped_package_locked(
	const struct pqcp_sovereign_evidence_packager *packager,
	const struct pqcp_sovereign_export_cursor *cursor)
{
	const struct pqcp_sovereign_evidence_package *selected = NULL;
	size_t index;

	for (index = 0U; index < packager->package_capacity; ++index) {
		const struct pqcp_sovereign_evidence_package *candidate =
			&packager->packages[index];

		if (!candidate->occupied || !candidate->sealed ||
		    candidate->package_id < cursor->next_package_id ||
		    strcmp(candidate->framework,
			   cursor->framework) != 0 ||
		    !same_tenant_scope(
			    candidate->subject_id,
			    sizeof(candidate->subject_id),
			    cursor->consumer_id,
			    sizeof(cursor->consumer_id))) {
			continue;
		}
		if (selected == NULL ||
		    candidate->package_id < selected->package_id) {
			selected = candidate;
		}
	}
	return selected;
}

static int validate_export_package(
	const struct pqcp_sovereign_export_cursor *cursor,
	const struct pqcp_sovereign_evidence_package *package)
{
	if (cursor == NULL || package == NULL ||
	    !package->occupied || !package->sealed ||
	    package->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    package->package_id == 0U ||
	    digest_all_zero(package->package_digest) ||
	    strcmp(package->framework, cursor->framework) != 0 ||
	    !same_tenant_scope(
		    package->subject_id,
		    sizeof(package->subject_id),
		    cursor->consumer_id,
		    sizeof(cursor->consumer_id))) {
		return -EBADMSG;
	}
	if (package->policy_epoch != cursor->policy_epoch) {
		return -ESTALE;
	}
	return 0;
}

int pqcp_sovereign_regulator_exporter_init(
	struct pqcp_sovereign_regulator_exporter *exporter,
	struct pqcp_sovereign_export_cursor *cursors,
	size_t capacity)
{
	if (exporter == NULL || cursors == NULL ||
	    capacity == 0U ||
	    capacity > SIZE_MAX / sizeof(*cursors)) {
		return -EINVAL;
	}
	memset(exporter, 0, sizeof(*exporter));
	memset(cursors, 0, capacity * sizeof(*cursors));
	exporter->schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	exporter->cursors = cursors;
	exporter->capacity = capacity;
	exporter->next_cursor_id = 1U;
	k_mutex_init(&exporter->lock);
	exporter->initialized = true;
	return 0;
}

int pqcp_sovereign_regulator_export_open(
	struct pqcp_sovereign_regulator_exporter *exporter,
	const char *consumer_id,
	const char *framework,
	uint64_t first_package_id,
	uint32_t maximum_batch,
	uint64_t policy_epoch,
	uint64_t now_ms,
	uint64_t expires_at_ms,
	struct pqcp_sovereign_export_cursor **cursor)
{
	struct pqcp_sovereign_export_cursor staged;
	struct pqcp_sovereign_export_cursor *slot;
	uint64_t cursor_id;
	int ret;

	if (exporter == NULL || !exporter->initialized ||
	    cursor == NULL ||
	    !scoped_identity_valid(
		    consumer_id, PQCP_SOVEREIGN_ID_MAX_CHARS) ||
	    !canonical_token_valid(
		    framework, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    first_package_id == 0U || maximum_batch == 0U ||
	    policy_epoch == 0U || now_ms == 0U ||
	    expires_at_ms <= now_ms) {
		return -EINVAL;
	}
	*cursor = NULL;
	ret = exporter_lock(exporter);
	if (ret != 0) {
		return ret;
	}
	if (exporter->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    exporter->cursors == NULL ||
	    exporter->capacity == 0U) {
		ret = -EBADMSG;
		goto out;
	}
	if (active_cursor_alias_locked(
		    exporter, consumer_id, framework)) {
		ret = -EALREADY;
		goto out;
	}
	slot = free_cursor_locked(exporter);
	if (slot == NULL) {
		ret = -ENOSPC;
		goto out;
	}
	if (exporter->next_cursor_id == 0U ||
	    exporter->next_cursor_id == UINT64_MAX) {
		ret = -EOVERFLOW;
		goto out;
	}
	cursor_id = exporter->next_cursor_id;
	memset(&staged, 0, sizeof(staged));
	staged.schema_version = PQCP_SOVEREIGN_SCHEMA_VERSION;
	staged.cursor_id = cursor_id;
	staged.next_package_id = first_package_id;
	staged.acknowledged_package_id = first_package_id - 1U;
	staged.opened_at_ms = now_ms;
	staged.expires_at_ms = expires_at_ms;
	staged.policy_epoch = policy_epoch;
	staged.maximum_batch = maximum_batch;
	staged.state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	staged.occupied = true;
	ret = copy_text(staged.consumer_id,
			sizeof(staged.consumer_id), consumer_id);
	if (ret == 0) {
		ret = copy_text(staged.framework,
				sizeof(staged.framework), framework);
	}
	if (ret != 0) {
		memset(&staged, 0, sizeof(staged));
		goto out;
	}
	*slot = staged;
	exporter->next_cursor_id = cursor_id + 1U;
	*cursor = slot;
	memset(&staged, 0, sizeof(staged));

out:
	exporter_unlock(exporter);
	return ret;
}

int pqcp_sovereign_regulator_export_next(
	struct pqcp_sovereign_regulator_exporter *exporter,
	struct pqcp_sovereign_evidence_packager *packager,
	uint64_t cursor_id,
	uint64_t now_ms,
	struct pqcp_sovereign_evidence_package **package)
{
	const struct pqcp_sovereign_evidence_package *selected;
	struct pqcp_sovereign_export_cursor *cursor;
	uint64_t outstanding_id;
	int ret;

	if (exporter == NULL || !exporter->initialized ||
	    packager == NULL || !packager->initialized ||
	    cursor_id == 0U || now_ms == 0U ||
	    package == NULL) {
		return -EINVAL;
	}
	*package = NULL;
	ret = pqcp_sovereign_evidence_packager_audit(packager);
	if (ret != 0) {
		return ret;
	}
	ret = exporter_lock(exporter);
	if (ret != 0) {
		return ret;
	}
	cursor = find_cursor_locked(exporter, cursor_id);
	if (cursor == NULL) {
		ret = -ENOENT;
		goto out_exporter;
	}
	if (!cursor_structurally_valid(cursor)) {
		ret = -EBADMSG;
		goto out_exporter;
	}
	if (cursor->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		ret = -EPERM;
		goto out_exporter;
	}
	if (now_ms >= cursor->expires_at_ms) {
		cursor->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
		ret = -ETIME;
		goto out_exporter;
	}
	ret = packager_lock(packager);
	if (ret != 0) {
		goto out_exporter;
	}
	if (cursor_has_outstanding(cursor)) {
		outstanding_id = cursor->next_package_id - 1U;
		selected = find_exact_package_locked(
			packager, outstanding_id);
		ret = validate_export_package(cursor, selected);
		if (ret == 0) {
			*package =
				(struct pqcp_sovereign_evidence_package *)
				selected;
		}
		goto out_packager;
	}
	if (cursor->maximum_batch == 0U) {
		cursor->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
		ret = -ENODATA;
		goto out_packager;
	}
	selected = find_next_scoped_package_locked(packager, cursor);
	if (selected == NULL) {
		ret = -ENODATA;
		goto out_packager;
	}
	ret = validate_export_package(cursor, selected);
	if (ret != 0) {
		goto out_packager;
	}
	if (selected->package_id == UINT64_MAX) {
		ret = -EOVERFLOW;
		goto out_packager;
	}
	cursor->acknowledged_package_id =
		selected->package_id - 1U;
	cursor->next_package_id = selected->package_id + 1U;
	cursor->maximum_batch--;
	if (exporter->export_count == UINT64_MAX) {
		cursor->next_package_id = selected->package_id;
		cursor->acknowledged_package_id =
			selected->package_id - 1U;
		cursor->maximum_batch++;
		ret = -EOVERFLOW;
		goto out_packager;
	}
	exporter->export_count++;
	*package =
		(struct pqcp_sovereign_evidence_package *)selected;
	ret = 0;

out_packager:
	packager_unlock(packager);
out_exporter:
	exporter_unlock(exporter);
	return ret;
}

int pqcp_sovereign_regulator_export_acknowledge(
	struct pqcp_sovereign_regulator_exporter *exporter,
	uint64_t cursor_id,
	uint64_t package_id)
{
	struct pqcp_sovereign_export_cursor *cursor;
	uint64_t expected_package_id;
	int ret;

	if (exporter == NULL || !exporter->initialized ||
	    cursor_id == 0U || package_id == 0U) {
		return -EINVAL;
	}
	ret = exporter_lock(exporter);
	if (ret != 0) {
		return ret;
	}
	cursor = find_cursor_locked(exporter, cursor_id);
	if (cursor == NULL) {
		ret = -ENOENT;
		goto out;
	}
	if (!cursor_structurally_valid(cursor)) {
		ret = -EBADMSG;
		goto out;
	}
	if (cursor->state != PQCP_SOVEREIGN_LIFECYCLE_ACTIVE) {
		ret = -EPERM;
		goto out;
	}
	if (!cursor_has_outstanding(cursor)) {
		ret = package_id == cursor->acknowledged_package_id ?
			-EALREADY : -EPROTO;
		goto out;
	}
	expected_package_id = cursor->next_package_id - 1U;
	if (package_id != expected_package_id ||
	    cursor->acknowledged_package_id + 1U !=
		    expected_package_id) {
		ret = -EPROTO;
		goto out;
	}
	cursor->acknowledged_package_id = package_id;
	if (cursor->maximum_batch == 0U) {
		cursor->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
	}
	ret = 0;

out:
	exporter_unlock(exporter);
	return ret;
}

int pqcp_sovereign_regulator_export_tick(
	struct pqcp_sovereign_regulator_exporter *exporter,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	size_t index;
	int ret;

	if (exporter == NULL || !exporter->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	ret = exporter_lock(exporter);
	if (ret != 0) {
		return ret;
	}
	for (index = 0U; index < exporter->capacity; ++index) {
		struct pqcp_sovereign_export_cursor *cursor =
			&exporter->cursors[index];

		if (!cursor->occupied ||
		    cursor->state !=
			    PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    cursor->expires_at_ms > now_ms) {
			continue;
		}
		if (expired == UINT32_MAX) {
			ret = -EOVERFLOW;
			goto out;
		}
		cursor->state = PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
		expired++;
	}
	*expired_count = expired;
	ret = 0;

out:
	exporter_unlock(exporter);
	return ret;
}

int pqcp_sovereign_regulator_exporter_audit(
	struct pqcp_sovereign_regulator_exporter *exporter)
{
	uint64_t maximum_cursor_id = 0U;
	uint64_t occupied_count = 0U;
	size_t index;
	size_t other;
	int ret;

	if (exporter == NULL || !exporter->initialized ||
	    exporter->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    exporter->cursors == NULL ||
	    exporter->capacity == 0U ||
	    exporter->next_cursor_id == 0U) {
		return -EINVAL;
	}
	ret = exporter_lock(exporter);
	if (ret != 0) {
		return ret;
	}
	for (index = 0U; index < exporter->capacity; ++index) {
		const struct pqcp_sovereign_export_cursor *cursor =
			&exporter->cursors[index];

		if (!cursor->occupied) {
			if (!bytes_all_zero(cursor, sizeof(*cursor))) {
				ret = -EBADMSG;
				goto out;
			}
			continue;
		}
		if (!cursor_structurally_valid(cursor)) {
			ret = -EBADMSG;
			goto out;
		}
		occupied_count++;
		if (cursor->cursor_id > maximum_cursor_id) {
			maximum_cursor_id = cursor->cursor_id;
		}
		for (other = index + 1U;
		     other < exporter->capacity; ++other) {
			const struct pqcp_sovereign_export_cursor *candidate =
				&exporter->cursors[other];

			if (!candidate->occupied) {
				continue;
			}
			if (candidate->cursor_id == cursor->cursor_id) {
				ret = -EEXIST;
				goto out;
			}
			if (cursor->state ==
				    PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
			    candidate->state ==
				    PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
			    strcmp(candidate->consumer_id,
				   cursor->consumer_id) == 0 &&
			    strcmp(candidate->framework,
				   cursor->framework) == 0) {
				ret = -EALREADY;
				goto out;
			}
		}
	}
	if (occupied_count != maximum_cursor_id ||
	    exporter->next_cursor_id != maximum_cursor_id + 1U) {
		ret = -EBADMSG;
		goto out;
	}
	ret = 0;

out:
	exporter_unlock(exporter);
	return ret;
}
