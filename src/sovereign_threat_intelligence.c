/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free sovereign threat-indicator intelligence registry.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "sovereign_policy_internal.h"

#define THREAT_SCORE_MAX 10000U
#define THREAT_CANONICAL_BYTES 512U

struct threat_writer {
	uint8_t *buffer;
	size_t capacity;
	size_t offset;
	int error;
};

static void threat_write_bytes(
	struct threat_writer *writer,
	const void *value,
	size_t length)
{
	if (writer == NULL || writer->error != 0) {
		return;
	}
	if ((value == NULL && length != 0U) ||
	    writer->offset > writer->capacity ||
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

static void threat_write_u16(
	struct threat_writer *writer,
	uint16_t value)
{
	uint8_t encoded[2];

	pqcp_sovereign_policy_write_u16(encoded, value);
	threat_write_bytes(writer, encoded, sizeof(encoded));
}

static void threat_write_u32(
	struct threat_writer *writer,
	uint32_t value)
{
	uint8_t encoded[4];

	pqcp_sovereign_policy_write_u32(encoded, value);
	threat_write_bytes(writer, encoded, sizeof(encoded));
}

static void threat_write_u64(
	struct threat_writer *writer,
	uint64_t value)
{
	uint8_t encoded[8];

	pqcp_sovereign_policy_write_u64(encoded, value);
	threat_write_bytes(writer, encoded, sizeof(encoded));
}

static bool threat_value_valid(
	const char *value,
	size_t capacity)
{
	size_t length;

	if (value == NULL || capacity < 2U) {
		return false;
	}
	length = strnlen(value, capacity);
	if (length == 0U || length >= capacity) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		const unsigned char character =
			(unsigned char)value[index];

		if (character < 0x21U || character > 0x7eU) {
			return false;
		}
	}
	return true;
}

static void threat_write_text(
	struct threat_writer *writer,
	const char *value,
	size_t capacity,
	bool uri_text)
{
	size_t length;
	bool valid;

	valid = uri_text ?
		threat_value_valid(value, capacity) :
		pqcp_sovereign_policy_text_valid(value, capacity);
	if (!valid) {
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
	threat_write_u16(writer, (uint16_t)length);
	threat_write_bytes(writer, value, length);
}

static bool threat_state_valid(
	enum pqcp_sovereign_lifecycle_state state)
{
	return state == PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
	       state == PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED ||
	       state == PQCP_SOVEREIGN_LIFECYCLE_RETIRED ||
	       state == PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
}

static bool threat_indicator_shape_valid(
	const struct pqcp_sovereign_threat_indicator *indicator,
	bool require_digest)
{
	return indicator != NULL &&
	       indicator->schema_version ==
		       PQCP_SOVEREIGN_SCHEMA_VERSION &&
	       indicator->indicator_id != 0U &&
	       pqcp_sovereign_policy_text_valid(
		       indicator->indicator_type,
		       sizeof(indicator->indicator_type)) &&
	       threat_value_valid(
		       indicator->value, sizeof(indicator->value)) &&
	       pqcp_sovereign_policy_text_valid(
		       indicator->source, sizeof(indicator->source)) &&
	       indicator->first_seen_ms != 0U &&
	       indicator->last_seen_ms >= indicator->first_seen_ms &&
	       indicator->expires_at_ms > indicator->last_seen_ms &&
	       indicator->policy_epoch != 0U &&
	       indicator->confidence_basis_points != 0U &&
	       indicator->confidence_basis_points <= THREAT_SCORE_MAX &&
	       indicator->severity != 0U &&
	       indicator->severity <= THREAT_SCORE_MAX &&
	       (indicator->tactic_mask != 0U ||
		indicator->technique_mask != 0U) &&
	       (!require_digest ||
		!pqcp_sovereign_policy_all_zero(
			indicator->indicator_digest,
			sizeof(indicator->indicator_digest))) &&
	       threat_state_valid(indicator->state) &&
	       indicator->occupied;
}

static bool threat_indicator_input_valid(
	const struct pqcp_sovereign_threat_indicator *indicator,
	uint64_t now_ms)
{
	struct pqcp_sovereign_threat_indicator candidate;

	if (indicator == NULL || indicator->occupied ||
	    now_ms == 0U ||
	    indicator->first_seen_ms > now_ms ||
	    indicator->last_seen_ms > now_ms ||
	    indicator->expires_at_ms <= now_ms) {
		return false;
	}
	candidate = *indicator;
	candidate.schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	if (candidate.indicator_id == 0U) {
		candidate.indicator_id = 1U;
	}
	if (candidate.state ==
		    PQCP_SOVEREIGN_LIFECYCLE_EMPTY ||
	    candidate.state ==
		    PQCP_SOVEREIGN_LIFECYCLE_DRAFT) {
		candidate.state =
			PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	}
	candidate.occupied = true;
	return candidate.state ==
		       PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
	       threat_indicator_shape_valid(&candidate, false);
}

static int threat_indicator_digest(
	const struct pqcp_sovereign_threat_indicator *indicator,
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	uint8_t canonical[THREAT_CANONICAL_BYTES];
	struct threat_writer writer = {
		.buffer = canonical,
		.capacity = sizeof(canonical),
	};
	int ret;

	if (!threat_indicator_shape_valid(indicator, false) ||
	    digest == NULL) {
		return -EINVAL;
	}
	memset(canonical, 0, sizeof(canonical));
	threat_write_bytes(
		&writer, "PQCP-SOVEREIGN-THREAT-INDICATOR-V1", 34U);
	threat_write_u32(
		&writer, indicator->schema_version);
	threat_write_u64(
		&writer, indicator->indicator_id);
	threat_write_text(
		&writer, indicator->indicator_type,
		sizeof(indicator->indicator_type), false);
	threat_write_text(
		&writer, indicator->value,
		sizeof(indicator->value), true);
	threat_write_text(
		&writer, indicator->source,
		sizeof(indicator->source), false);
	threat_write_u64(
		&writer, indicator->first_seen_ms);
	threat_write_u64(
		&writer, indicator->last_seen_ms);
	threat_write_u64(
		&writer, indicator->expires_at_ms);
	threat_write_u64(
		&writer, indicator->policy_epoch);
	threat_write_u32(
		&writer, indicator->confidence_basis_points);
	threat_write_u32(
		&writer, indicator->severity);
	threat_write_u64(
		&writer, indicator->tactic_mask);
	threat_write_u64(
		&writer, indicator->technique_mask);
	threat_write_u32(
		&writer, (uint32_t)indicator->state);
	if (writer.error != 0) {
		memset(canonical, 0, sizeof(canonical));
		return writer.error;
	}
	ret = pqcp_sovereign_policy_sha256(
		canonical, writer.offset, digest);
	memset(canonical, 0, sizeof(canonical));
	return ret;
}

static int threat_lock(
	struct pqcp_sovereign_threat_intelligence *intelligence)
{
	if (intelligence == NULL ||
	    !intelligence->initialized) {
		return -EINVAL;
	}
	return k_mutex_lock(
		&intelligence->lock, K_FOREVER);
}

static void threat_unlock(
	struct pqcp_sovereign_threat_intelligence *intelligence)
{
	(void)k_mutex_unlock(&intelligence->lock);
}

static int threat_indicator_index_by_id_locked(
	const struct pqcp_sovereign_threat_intelligence *intelligence,
	uint64_t indicator_id)
{
	if (indicator_id == 0U) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < intelligence->capacity; ++index) {
		if (intelligence->indicators[index].occupied &&
		    intelligence->indicators[index].indicator_id ==
			    indicator_id) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int threat_indicator_index_by_identity_locked(
	const struct pqcp_sovereign_threat_intelligence *intelligence,
	const char *indicator_type,
	const char *value)
{
	for (size_t index = 0U;
	     index < intelligence->capacity; ++index) {
		const struct pqcp_sovereign_threat_indicator *indicator =
			&intelligence->indicators[index];

		if (indicator->occupied &&
		    strcmp(indicator->indicator_type,
			   indicator_type) == 0 &&
		    strcmp(indicator->value, value) == 0) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static int threat_free_index_locked(
	const struct pqcp_sovereign_threat_intelligence *intelligence)
{
	for (size_t index = 0U;
	     index < intelligence->capacity; ++index) {
		if (!intelligence->indicators[index].occupied) {
			return (int)index;
		}
	}
	return -ENOSPC;
}

static int threat_assign_id_locked(
	struct pqcp_sovereign_threat_intelligence *intelligence,
	uint64_t *indicator_id)
{
	uint64_t candidate;
	size_t attempts = 0U;

	while (attempts <= intelligence->capacity) {
		candidate = intelligence->next_indicator_id;
		if (candidate == 0U) {
			candidate = 1U;
		}
		intelligence->next_indicator_id =
			candidate == UINT64_MAX ? 1U : candidate + 1U;
		if (threat_indicator_index_by_id_locked(
			    intelligence, candidate) == -ENOENT) {
			*indicator_id = candidate;
			return 0;
		}
		attempts++;
	}
	return -EOVERFLOW;
}

static bool threat_indicators_equivalent(
	const struct pqcp_sovereign_threat_indicator *left,
	const struct pqcp_sovereign_threat_indicator *right)
{
	return left->indicator_id == right->indicator_id &&
	       strcmp(left->indicator_type,
		      right->indicator_type) == 0 &&
	       strcmp(left->value, right->value) == 0 &&
	       strcmp(left->source, right->source) == 0 &&
	       left->first_seen_ms == right->first_seen_ms &&
	       left->last_seen_ms == right->last_seen_ms &&
	       left->expires_at_ms == right->expires_at_ms &&
	       left->policy_epoch == right->policy_epoch &&
	       left->confidence_basis_points ==
		       right->confidence_basis_points &&
	       left->severity == right->severity &&
	       left->tactic_mask == right->tactic_mask &&
	       left->technique_mask == right->technique_mask &&
	       left->state == right->state;
}

int pqcp_sovereign_threat_intelligence_init(
	struct pqcp_sovereign_threat_intelligence *intelligence,
	struct pqcp_sovereign_threat_indicator *indicators,
	size_t capacity)
{
	if (intelligence == NULL || indicators == NULL ||
	    capacity == 0U || capacity > INT_MAX) {
		return -EINVAL;
	}
	memset(intelligence, 0, sizeof(*intelligence));
	memset(indicators, 0, capacity * sizeof(*indicators));
	intelligence->schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	intelligence->indicators = indicators;
	intelligence->capacity = capacity;
	intelligence->next_indicator_id = 1U;
	k_mutex_init(&intelligence->lock);
	intelligence->initialized = true;
	return 0;
}

int pqcp_sovereign_threat_indicator_put(
	struct pqcp_sovereign_threat_intelligence *intelligence,
	const struct pqcp_sovereign_threat_indicator *indicator,
	uint64_t now_ms)
{
	struct pqcp_sovereign_threat_indicator candidate;
	const struct pqcp_sovereign_threat_indicator *existing;
	uint8_t supplied_digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int identity_index;
	int index;
	int ret;

	if (!threat_indicator_input_valid(indicator, now_ms)) {
		return -EINVAL;
	}
	ret = threat_lock(intelligence);
	if (ret != 0) {
		return ret;
	}
	candidate = *indicator;
	candidate.schema_version =
		PQCP_SOVEREIGN_SCHEMA_VERSION;
	candidate.state = PQCP_SOVEREIGN_LIFECYCLE_ACTIVE;
	candidate.occupied = true;
	if (candidate.indicator_id == 0U) {
		ret = threat_assign_id_locked(
			intelligence, &candidate.indicator_id);
		if (ret != 0) {
			threat_unlock(intelligence);
			return ret;
		}
		index = threat_free_index_locked(intelligence);
	} else {
		index = threat_indicator_index_by_id_locked(
			intelligence, candidate.indicator_id);
		if (index < 0 && index != -ENOENT) {
			threat_unlock(intelligence);
			return index;
		}
		if (index < 0) {
			index = threat_free_index_locked(intelligence);
		}
	}
	if (index < 0) {
		threat_unlock(intelligence);
		return index;
	}
	identity_index =
		threat_indicator_index_by_identity_locked(
			intelligence, candidate.indicator_type,
			candidate.value);
	if (identity_index >= 0 && identity_index != index) {
		threat_unlock(intelligence);
		return -EEXIST;
	}
	if (intelligence->indicators[index].occupied) {
		existing = &intelligence->indicators[index];
		if (strcmp(existing->indicator_type,
			   candidate.indicator_type) != 0 ||
		    strcmp(existing->value, candidate.value) != 0 ||
		    strcmp(existing->source, candidate.source) != 0 ||
		    existing->first_seen_ms !=
			    candidate.first_seen_ms) {
			threat_unlock(intelligence);
			return -EACCES;
		}
		if (existing->state ==
		    PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
			threat_unlock(intelligence);
			return -EPERM;
		}
		if (threat_indicators_equivalent(
			    existing, &candidate)) {
			threat_unlock(intelligence);
			return 0;
		}
		if (candidate.policy_epoch <
			    existing->policy_epoch ||
		    candidate.last_seen_ms <=
			    existing->last_seen_ms ||
		    candidate.expires_at_ms <
			    existing->expires_at_ms) {
			threat_unlock(intelligence);
			return -ESTALE;
		}
	}
	memcpy(supplied_digest, candidate.indicator_digest,
	       sizeof(supplied_digest));
	memset(candidate.indicator_digest, 0,
	       sizeof(candidate.indicator_digest));
	ret = threat_indicator_digest(
		&candidate, candidate.indicator_digest);
	if (ret != 0) {
		threat_unlock(intelligence);
		return ret;
	}
	if (!pqcp_sovereign_policy_all_zero(
		    supplied_digest, sizeof(supplied_digest)) &&
	    !pqcp_sovereign_policy_equal(
		    supplied_digest, candidate.indicator_digest,
		    sizeof(supplied_digest))) {
		memset(candidate.indicator_digest, 0,
		       sizeof(candidate.indicator_digest));
		threat_unlock(intelligence);
		return -EBADMSG;
	}
	intelligence->indicators[index] = candidate;
	memset(supplied_digest, 0, sizeof(supplied_digest));
	threat_unlock(intelligence);
	return 0;
}

int pqcp_sovereign_threat_match(
	struct pqcp_sovereign_threat_intelligence *intelligence,
	const char *indicator_type,
	const char *value,
	uint64_t now_ms,
	struct pqcp_sovereign_threat_indicator **indicator)
{
	struct pqcp_sovereign_threat_indicator *selected = NULL;
	int ret;

	if (!pqcp_sovereign_policy_text_valid(
		    indicator_type, PQCP_SOVEREIGN_LABEL_MAX_CHARS) ||
	    !threat_value_valid(
		    value, PQCP_SOVEREIGN_URI_MAX_CHARS) ||
	    now_ms == 0U || indicator == NULL) {
		return -EINVAL;
	}
	*indicator = NULL;
	ret = threat_lock(intelligence);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < intelligence->capacity; ++index) {
		struct pqcp_sovereign_threat_indicator *candidate =
			&intelligence->indicators[index];

		if (!candidate->occupied ||
		    candidate->state !=
			    PQCP_SOVEREIGN_LIFECYCLE_ACTIVE ||
		    now_ms < candidate->first_seen_ms ||
		    now_ms >= candidate->expires_at_ms ||
		    strcmp(candidate->indicator_type,
			   indicator_type) != 0 ||
		    strcmp(candidate->value, value) != 0) {
			continue;
		}
		if (selected == NULL ||
		    candidate->confidence_basis_points >
			    selected->confidence_basis_points ||
		    (candidate->confidence_basis_points ==
			     selected->confidence_basis_points &&
		     candidate->severity > selected->severity) ||
		    (candidate->confidence_basis_points ==
			     selected->confidence_basis_points &&
		     candidate->severity == selected->severity &&
		     candidate->last_seen_ms >
			     selected->last_seen_ms)) {
			selected = candidate;
		}
	}
	if (selected == NULL) {
		threat_unlock(intelligence);
		return -ENOENT;
	}
	intelligence->match_count =
		pqcp_sovereign_policy_add_u64(
			intelligence->match_count, 1U);
	*indicator = selected;
	threat_unlock(intelligence);
	return 0;
}

int pqcp_sovereign_threat_revoke(
	struct pqcp_sovereign_threat_intelligence *intelligence,
	uint64_t indicator_id)
{
	struct pqcp_sovereign_threat_indicator candidate;
	int index;
	int ret;

	if (indicator_id == 0U) {
		return -EINVAL;
	}
	ret = threat_lock(intelligence);
	if (ret != 0) {
		return ret;
	}
	index = threat_indicator_index_by_id_locked(
		intelligence, indicator_id);
	if (index < 0) {
		threat_unlock(intelligence);
		return index;
	}
	if (intelligence->indicators[index].state ==
	    PQCP_SOVEREIGN_LIFECYCLE_REVOKED) {
		threat_unlock(intelligence);
		return -EALREADY;
	}
	candidate = intelligence->indicators[index];
	candidate.state =
		PQCP_SOVEREIGN_LIFECYCLE_REVOKED;
	memset(candidate.indicator_digest, 0,
	       sizeof(candidate.indicator_digest));
	ret = threat_indicator_digest(
		&candidate, candidate.indicator_digest);
	if (ret == 0) {
		intelligence->indicators[index] = candidate;
	}
	threat_unlock(intelligence);
	return ret;
}

int pqcp_sovereign_threat_tick(
	struct pqcp_sovereign_threat_intelligence *intelligence,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t count = 0U;
	int ret;

	if (now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	*expired_count = 0U;
	ret = threat_lock(intelligence);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < intelligence->capacity; ++index) {
		struct pqcp_sovereign_threat_indicator candidate;
		struct pqcp_sovereign_threat_indicator *indicator =
			&intelligence->indicators[index];

		if (!indicator->occupied ||
		    (indicator->state !=
			     PQCP_SOVEREIGN_LIFECYCLE_ACTIVE &&
		     indicator->state !=
			     PQCP_SOVEREIGN_LIFECYCLE_SUSPENDED) ||
		    indicator->expires_at_ms > now_ms) {
			continue;
		}
		candidate = *indicator;
		candidate.state =
			PQCP_SOVEREIGN_LIFECYCLE_RETIRED;
		memset(candidate.indicator_digest, 0,
		       sizeof(candidate.indicator_digest));
		ret = threat_indicator_digest(
			&candidate, candidate.indicator_digest);
		if (ret != 0) {
			threat_unlock(intelligence);
			return ret;
		}
		*indicator = candidate;
		intelligence->expiry_count =
			pqcp_sovereign_policy_add_u64(
				intelligence->expiry_count, 1U);
		if (count != UINT32_MAX) {
			count++;
		}
	}
	*expired_count = count;
	threat_unlock(intelligence);
	return 0;
}

int pqcp_sovereign_threat_intelligence_audit(
	struct pqcp_sovereign_threat_intelligence *intelligence)
{
	uint8_t digest[PQCP_SOVEREIGN_DIGEST_BYTES];
	int ret;

	if (intelligence == NULL ||
	    !intelligence->initialized ||
	    intelligence->schema_version !=
		    PQCP_SOVEREIGN_SCHEMA_VERSION ||
	    intelligence->indicators == NULL ||
	    intelligence->capacity == 0U ||
	    intelligence->capacity > INT_MAX ||
	    intelligence->next_indicator_id == 0U) {
		return -EINVAL;
	}
	ret = threat_lock(intelligence);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < intelligence->capacity; ++index) {
		const struct pqcp_sovereign_threat_indicator *indicator =
			&intelligence->indicators[index];

		if (!indicator->occupied) {
			continue;
		}
		if (!threat_indicator_shape_valid(
			    indicator, true)) {
			ret = -EBADMSG;
			goto out;
		}
		ret = threat_indicator_digest(indicator, digest);
		if (ret != 0 ||
		    !pqcp_sovereign_policy_equal(
			    digest, indicator->indicator_digest,
			    sizeof(digest))) {
			ret = ret != 0 ? ret : -EBADMSG;
			goto out;
		}
		for (size_t other = index + 1U;
		     other < intelligence->capacity; ++other) {
			const struct pqcp_sovereign_threat_indicator *peer =
				&intelligence->indicators[other];

			if (!peer->occupied) {
				continue;
			}
			if (peer->indicator_id ==
			    indicator->indicator_id) {
				ret = -EEXIST;
				goto out;
			}
			if (strcmp(peer->indicator_type,
				   indicator->indicator_type) == 0 &&
			    strcmp(peer->value,
				   indicator->value) == 0) {
				ret = -EEXIST;
				goto out;
			}
		}
	}
	ret = 0;
out:
	memset(digest, 0, sizeof(digest));
	threat_unlock(intelligence);
	return ret;
}
