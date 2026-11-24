/*
 * SPDX-License-Identifier: MIT
 *
 * Secret-free runtime snapshot format.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime.h>

#include "runtime_internal.h"

#define PQCP_RUNTIME_SNAPSHOT_MAGIC UINT32_C(0x50515253)
#define PQCP_RUNTIME_SNAPSHOT_HEADER_BYTES 32U
#define PQCP_RUNTIME_SNAPSHOT_SESSION_BYTES 160U
#define PQCP_RUNTIME_SNAPSHOT_PROFILE_BYTES 160U

static int snapshot_size(size_t session_count, size_t profile_count,
			 size_t *required)
{
	const size_t overhead = PQCP_RUNTIME_SNAPSHOT_HEADER_BYTES +
		PQCP_RUNTIME_DIGEST_BYTES;
	const size_t limit = (UINT32_MAX - overhead) /
		PQCP_RUNTIME_SNAPSHOT_SESSION_BYTES;

	_Static_assert(PQCP_RUNTIME_SNAPSHOT_SESSION_BYTES ==
		       PQCP_RUNTIME_SNAPSHOT_PROFILE_BYTES,
		       "snapshot record sizes must match");
	if (session_count > limit || profile_count > limit - session_count) {
		return -EINVAL;
	}
	*required = overhead + (session_count + profile_count) *
		PQCP_RUNTIME_SNAPSHOT_SESSION_BYTES;
	return 0;
}

static bool buffers_overlap(const void *first, size_t first_size,
			    const void *second, size_t second_size)
{
	const uintptr_t a = (uintptr_t)first;
	const uintptr_t b = (uintptr_t)second;

	if (first_size == 0U || second_size == 0U) {
		return false;
	}
	return a <= b ? b - a < first_size : a - b < second_size;
}

static bool session_valid(const struct pqcp_runtime_session *session)
{
	return session->schema_version == PQCP_RUNTIME_SCHEMA_VERSION &&
		session->session_id != 0U && session->active &&
		pqcp_runtime_internal_text_valid(session->profile_id,
						sizeof(session->profile_id));
}

static bool profile_valid(const struct pqcp_runtime_profile_state *profile)
{
	return profile->schema_version == PQCP_RUNTIME_SCHEMA_VERSION &&
		pqcp_runtime_internal_text_valid(profile->profile_id,
						sizeof(profile->profile_id)) &&
		(unsigned int)profile->latency_source <= PQCP_RUNTIME_METRIC_CALIBRATED &&
		(unsigned int)profile->cycles_source <= PQCP_RUNTIME_METRIC_CALIBRATED &&
		(unsigned int)profile->memory_source <= PQCP_RUNTIME_METRIC_CALIBRATED &&
		(unsigned int)profile->energy_source <= PQCP_RUNTIME_METRIC_CALIBRATED &&
		(uint64_t)profile->successful_observations +
			profile->failed_observations == profile->observation_count;
}

static void write_handle(
	uint8_t *output,
	const struct pqcp_runtime_key_handle *handle)
{
	pqcp_runtime_internal_write_u32(output, handle->slot);
	pqcp_runtime_internal_write_u32(
		output + 4U, handle->generation);
	pqcp_runtime_internal_write_u32(
		output + 8U, (uint32_t)handle->backend);
	pqcp_runtime_internal_write_u32(
		output + 12U, (uint32_t)handle->family);
	pqcp_runtime_internal_write_u32(
		output + 16U, handle->level);
}

static void read_handle(
	const uint8_t *input,
	struct pqcp_runtime_key_handle *handle)
{
	handle->slot = pqcp_runtime_internal_read_u32(input);
	handle->generation =
		pqcp_runtime_internal_read_u32(input + 4U);
	handle->backend = (enum pqcp_runtime_key_backend)
		pqcp_runtime_internal_read_u32(input + 8U);
	handle->family = (enum pqcp_runtime_key_family)
		pqcp_runtime_internal_read_u32(input + 12U);
	handle->level =
		pqcp_runtime_internal_read_u32(input + 16U);
}

static size_t active_sessions(
	const struct pqcp_runtime_session *sessions,
	size_t capacity)
{
	size_t count = 0U;

	for (size_t index = 0U; index < capacity; ++index) {
		if (sessions[index].active) {
			count++;
		}
	}
	return count;
}

static size_t active_profiles(
	const struct pqcp_runtime_profile_state *profiles,
	size_t capacity)
{
	size_t count = 0U;

	for (size_t index = 0U; index < capacity; ++index) {
		if (profiles[index].schema_version ==
		    PQCP_RUNTIME_SCHEMA_VERSION) {
			count++;
		}
	}
	return count;
}

static int write_session(
	uint8_t *output,
	const struct pqcp_runtime_session *session)
{
	if (!session_valid(session)) {
		return -EINVAL;
	}
	memset(output, 0, PQCP_RUNTIME_SNAPSHOT_SESSION_BYTES);
	pqcp_runtime_internal_write_u32(
		output, session->schema_version);
	pqcp_runtime_internal_write_u64(
		output + 4U, session->session_id);
	pqcp_runtime_internal_write_u32(
		output + 12U, session->mlkem_level);
	pqcp_runtime_internal_write_u32(
		output + 16U, session->mldsa_level);
	pqcp_runtime_internal_write_u64(
		output + 20U, session->opened_at_ms);
	pqcp_runtime_internal_write_u64(
		output + 28U, session->expires_at_ms);
	pqcp_runtime_internal_write_u64(
		output + 36U, session->jobs_submitted);
	pqcp_runtime_internal_write_u64(
		output + 44U, session->jobs_completed);
	pqcp_runtime_internal_write_u64(
		output + 52U, session->failures);
	output[60] = 1U;
	output[61] = session->draining ? 1U : 0U;
	output[62] = session->protected_channel ? 1U : 0U;
	memcpy(output + 64U, session->profile_id,
	       strnlen(session->profile_id,
		       sizeof(session->profile_id)));
	write_handle(output + 112U, &session->kem_key);
	write_handle(output + 132U, &session->signing_key);
	return 0;
}

static int read_session(
	const uint8_t *input,
	struct pqcp_runtime_session *session)
{
	memset(session, 0, sizeof(*session));
	session->schema_version =
		pqcp_runtime_internal_read_u32(input);
	session->session_id =
		pqcp_runtime_internal_read_u64(input + 4U);
	session->mlkem_level =
		pqcp_runtime_internal_read_u32(input + 12U);
	session->mldsa_level =
		pqcp_runtime_internal_read_u32(input + 16U);
	session->opened_at_ms =
		pqcp_runtime_internal_read_u64(input + 20U);
	session->expires_at_ms =
		pqcp_runtime_internal_read_u64(input + 28U);
	session->jobs_submitted =
		pqcp_runtime_internal_read_u64(input + 36U);
	session->jobs_completed =
		pqcp_runtime_internal_read_u64(input + 44U);
	session->failures =
		pqcp_runtime_internal_read_u64(input + 52U);
	session->active = input[60] != 0U;
	session->draining = input[61] != 0U;
	session->protected_channel = input[62] != 0U;
	memcpy(session->profile_id, input + 64U,
	       sizeof(session->profile_id) - 1U);
	read_handle(input + 112U, &session->kem_key);
	read_handle(input + 132U, &session->signing_key);
	if (!session_valid(session) || input[60] != 1U ||
	    input[61] > 1U || input[62] > 1U ||
	    memchr(input + 64U, '\0', sizeof(session->profile_id)) == NULL) {
		pqcp_runtime_secure_zero(
			session, sizeof(*session));
		return -EBADMSG;
	}
	return 0;
}

static int write_profile(
	uint8_t *output,
	const struct pqcp_runtime_profile_state *profile)
{
	if (!profile_valid(profile)) {
		return -EINVAL;
	}
	memset(output, 0, PQCP_RUNTIME_SNAPSHOT_PROFILE_BYTES);
	pqcp_runtime_internal_write_u32(
		output, profile->schema_version);
	pqcp_runtime_internal_write_u32(
		output + 4U, profile->latency_source);
	pqcp_runtime_internal_write_u32(
		output + 8U, profile->cycles_source);
	pqcp_runtime_internal_write_u32(
		output + 12U, profile->memory_source);
	pqcp_runtime_internal_write_u32(
		output + 16U, profile->energy_source);
	pqcp_runtime_internal_write_u32(
		output + 20U, profile->observation_count);
	pqcp_runtime_internal_write_u32(
		output + 24U, profile->successful_observations);
	pqcp_runtime_internal_write_u32(
		output + 28U, profile->failed_observations);
	pqcp_runtime_internal_write_u64(
		output + 32U, profile->latency_ewma_us);
	pqcp_runtime_internal_write_u64(
		output + 40U, profile->cycles_ewma);
	pqcp_runtime_internal_write_u64(
		output + 48U, profile->stack_high_watermark);
	pqcp_runtime_internal_write_u64(
		output + 56U, profile->workspace_high_watermark);
	pqcp_runtime_internal_write_u64(
		output + 64U, profile->last_observed_at_ms);
	memcpy(output + 72U, profile->profile_id,
	       strnlen(profile->profile_id,
		       sizeof(profile->profile_id)));
	return 0;
}

static int read_profile(
	const uint8_t *input,
	struct pqcp_runtime_profile_state *profile)
{
	memset(profile, 0, sizeof(*profile));
	profile->schema_version =
		pqcp_runtime_internal_read_u32(input);
	profile->latency_source =
		pqcp_runtime_internal_read_u32(input + 4U);
	profile->cycles_source =
		pqcp_runtime_internal_read_u32(input + 8U);
	profile->memory_source =
		pqcp_runtime_internal_read_u32(input + 12U);
	profile->energy_source =
		pqcp_runtime_internal_read_u32(input + 16U);
	profile->observation_count =
		pqcp_runtime_internal_read_u32(input + 20U);
	profile->successful_observations =
		pqcp_runtime_internal_read_u32(input + 24U);
	profile->failed_observations =
		pqcp_runtime_internal_read_u32(input + 28U);
	profile->latency_ewma_us =
		pqcp_runtime_internal_read_u64(input + 32U);
	profile->cycles_ewma =
		pqcp_runtime_internal_read_u64(input + 40U);
	profile->stack_high_watermark =
		pqcp_runtime_internal_read_u64(input + 48U);
	profile->workspace_high_watermark =
		pqcp_runtime_internal_read_u64(input + 56U);
	profile->last_observed_at_ms =
		pqcp_runtime_internal_read_u64(input + 64U);
	memcpy(profile->profile_id, input + 72U,
	       sizeof(profile->profile_id) - 1U);
	if (!profile_valid(profile) ||
	    memchr(input + 72U, '\0', sizeof(profile->profile_id)) == NULL) {
		memset(profile, 0, sizeof(*profile));
		return -EBADMSG;
	}
	return 0;
}

int pqcp_runtime_snapshot_write(
	const struct pqcp_runtime_session *sessions,
	size_t session_capacity,
	const struct pqcp_runtime_profile_state *profiles,
	size_t profile_capacity,
	uint8_t *output,
	size_t output_capacity,
	struct pqcp_runtime_snapshot_info *info)
{
	size_t session_count;
	size_t profile_count;
	size_t required;
	size_t offset = PQCP_RUNTIME_SNAPSHOT_HEADER_BYTES;
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint32_t key_references = 0U;

	if (sessions == NULL || profiles == NULL ||
	    output == NULL || info == NULL ||
	    session_capacity > SIZE_MAX / sizeof(*sessions) ||
	    profile_capacity > SIZE_MAX / sizeof(*profiles) ||
	    snapshot_size(session_capacity, profile_capacity, &required) != 0) {
		return -EINVAL;
	}
	session_count = active_sessions(sessions, session_capacity);
	profile_count = active_profiles(profiles, profile_capacity);
	if (snapshot_size(session_count, profile_count, &required) != 0 ||
	    output_capacity < required ||
	    buffers_overlap(output, required, sessions,
			    session_capacity * sizeof(*sessions)) ||
	    buffers_overlap(output, required, profiles,
			    profile_capacity * sizeof(*profiles)) ||
	    buffers_overlap(output, required, info, sizeof(*info))) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < session_capacity; ++index) {
		if (sessions[index].active && !session_valid(&sessions[index])) {
			return -EBADMSG;
		}
	}
	for (size_t index = 0U; index < profile_capacity; ++index) {
		if (profiles[index].schema_version == PQCP_RUNTIME_SCHEMA_VERSION &&
		    !profile_valid(&profiles[index])) {
			return -EBADMSG;
		}
	}
	memset(output, 0, required);
	pqcp_runtime_internal_write_u32(
		output, PQCP_RUNTIME_SNAPSHOT_MAGIC);
	pqcp_runtime_internal_write_u32(
		output + 4U, PQCP_RUNTIME_SCHEMA_VERSION);
	pqcp_runtime_internal_write_u32(
		output + 8U, (uint32_t)required);
	pqcp_runtime_internal_write_u32(
		output + 12U, (uint32_t)session_count);
	pqcp_runtime_internal_write_u32(
		output + 16U, (uint32_t)profile_count);
	for (size_t index = 0U; index < session_capacity; ++index) {
		if (!sessions[index].active) {
			continue;
		}
		if (write_session(output + offset,
				  &sessions[index]) != 0) {
			return -EBADMSG;
		}
		if (pqcp_runtime_key_handle_is_valid(
			    &sessions[index].kem_key)) {
			key_references++;
		}
		if (pqcp_runtime_key_handle_is_valid(
			    &sessions[index].signing_key)) {
			key_references++;
		}
		offset += PQCP_RUNTIME_SNAPSHOT_SESSION_BYTES;
	}
	for (size_t index = 0U; index < profile_capacity; ++index) {
		if (profiles[index].schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION) {
			continue;
		}
		if (write_profile(output + offset,
				  &profiles[index]) != 0) {
			return -EBADMSG;
		}
		offset += PQCP_RUNTIME_SNAPSHOT_PROFILE_BYTES;
	}
	pqcp_runtime_internal_write_u32(
		output + 20U, key_references);
	if (pqcp_runtime_internal_sha256(
		    output, offset, digest) != 0) {
		return -EIO;
	}
	memcpy(output + offset, digest, sizeof(digest));
	memset(info, 0, sizeof(*info));
	info->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	info->bytes_written = (uint32_t)required;
	info->session_count = (uint32_t)session_count;
	info->profile_count = (uint32_t)profile_count;
	info->key_reference_count = key_references;
	(void)pqcp_runtime_internal_hex(
		digest, sizeof(digest), info->digest_hex,
		sizeof(info->digest_hex));
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return 0;
}

int pqcp_runtime_snapshot_read(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_runtime_session *sessions,
	size_t session_capacity,
	struct pqcp_runtime_profile_state *profiles,
	size_t profile_capacity,
	struct pqcp_runtime_snapshot_info *info)
{
	uint8_t digest[PQCP_RUNTIME_DIGEST_BYTES];
	uint32_t magic;
	uint32_t schema;
	uint32_t total;
	uint32_t session_count;
	uint32_t profile_count;
	uint32_t key_references;
	size_t digest_offset;
	size_t required;
	size_t offset = PQCP_RUNTIME_SNAPSHOT_HEADER_BYTES;
	uint32_t actual_references = 0U;

	if (input == NULL ||
	    input_length < PQCP_RUNTIME_SNAPSHOT_HEADER_BYTES +
			    PQCP_RUNTIME_DIGEST_BYTES ||
	    sessions == NULL || profiles == NULL || info == NULL ||
	    session_capacity > SIZE_MAX / sizeof(*sessions) ||
	    profile_capacity > SIZE_MAX / sizeof(*profiles) ||
	    buffers_overlap(input, input_length, sessions,
			    session_capacity * sizeof(*sessions)) ||
	    buffers_overlap(input, input_length, profiles,
			    profile_capacity * sizeof(*profiles)) ||
	    buffers_overlap(input, input_length, info, sizeof(*info)) ||
	    buffers_overlap(sessions, session_capacity * sizeof(*sessions),
			    profiles, profile_capacity * sizeof(*profiles)) ||
	    buffers_overlap(sessions, session_capacity * sizeof(*sessions),
			    info, sizeof(*info)) ||
	    buffers_overlap(profiles, profile_capacity * sizeof(*profiles),
			    info, sizeof(*info))) {
		return -EINVAL;
	}
	magic = pqcp_runtime_internal_read_u32(input);
	schema = pqcp_runtime_internal_read_u32(input + 4U);
	total = pqcp_runtime_internal_read_u32(input + 8U);
	session_count =
		pqcp_runtime_internal_read_u32(input + 12U);
	profile_count =
		pqcp_runtime_internal_read_u32(input + 16U);
	key_references =
		pqcp_runtime_internal_read_u32(input + 20U);
	if (magic != PQCP_RUNTIME_SNAPSHOT_MAGIC ||
	    schema != PQCP_RUNTIME_SCHEMA_VERSION ||
	    total != input_length ||
	    session_count > session_capacity ||
	    profile_count > profile_capacity ||
	    snapshot_size(session_count, profile_count, &required) != 0 ||
	    required != input_length) {
		return -EINVAL;
	}
	digest_offset = required - PQCP_RUNTIME_DIGEST_BYTES;
	if (pqcp_runtime_internal_sha256(
		    input, digest_offset, digest) != 0 ||
	    memcmp(digest, input + digest_offset,
		   sizeof(digest)) != 0) {
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		return -EBADMSG;
	}
	/* Validate every record before changing any caller-owned restore state. */
	for (uint32_t index = 0U; index < session_count; ++index) {
		struct pqcp_runtime_session decoded;

		if (read_session(input + offset, &decoded) != 0) {
			pqcp_runtime_secure_zero(digest, sizeof(digest));
			return -EBADMSG;
		}
		actual_references += pqcp_runtime_key_handle_is_valid(&decoded.kem_key);
		actual_references += pqcp_runtime_key_handle_is_valid(&decoded.signing_key);
		offset += PQCP_RUNTIME_SNAPSHOT_SESSION_BYTES;
	}
	for (uint32_t index = 0U; index < profile_count; ++index) {
		struct pqcp_runtime_profile_state decoded;

		if (read_profile(input + offset, &decoded) != 0) {
			pqcp_runtime_secure_zero(digest, sizeof(digest));
			return -EBADMSG;
		}
		offset += PQCP_RUNTIME_SNAPSHOT_PROFILE_BYTES;
	}
	if (actual_references != key_references) {
		pqcp_runtime_secure_zero(digest, sizeof(digest));
		return -EBADMSG;
	}
	offset = PQCP_RUNTIME_SNAPSHOT_HEADER_BYTES;
	memset(sessions, 0,
	       sizeof(*sessions) * session_capacity);
	memset(profiles, 0,
	       sizeof(*profiles) * profile_capacity);
	for (uint32_t index = 0U;
	     index < session_count; ++index) {
		(void)read_session(input + offset, &sessions[index]);
		offset += PQCP_RUNTIME_SNAPSHOT_SESSION_BYTES;
	}
	for (uint32_t index = 0U;
	     index < profile_count; ++index) {
		(void)read_profile(input + offset, &profiles[index]);
		offset += PQCP_RUNTIME_SNAPSHOT_PROFILE_BYTES;
	}
	memset(info, 0, sizeof(*info));
	info->schema_version = schema;
	info->bytes_written = total;
	info->session_count = session_count;
	info->profile_count = profile_count;
	info->key_reference_count = key_references;
	(void)pqcp_runtime_internal_hex(
		digest, sizeof(digest), info->digest_hex,
		sizeof(info->digest_hex));
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	return 0;
}
