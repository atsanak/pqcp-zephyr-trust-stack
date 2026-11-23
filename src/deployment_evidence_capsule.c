/*
 * SPDX-License-Identifier: MIT
 *
 * Firmware deployment evidence capsule builder.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_capsule.h>

#define CAPSULE_DOMAIN UINT64_C(0x5051435043415053)
#define CAPSULE_FORMAT_VERSION 1U
#define CAPSULE_HEADER_MAGIC_OFFSET 0U
#define CAPSULE_HEADER_SCHEMA_OFFSET 4U
#define CAPSULE_HEADER_FLAGS_OFFSET 8U
#define CAPSULE_HEADER_HEADER_BYTES_OFFSET 12U
#define CAPSULE_HEADER_RECORD_COUNT_OFFSET 16U
#define CAPSULE_HEADER_TOTAL_BYTES_OFFSET 20U
#define CAPSULE_HEADER_FORMAT_OFFSET 24U
#define CAPSULE_HEADER_RESERVED_OFFSET 28U

static bool passport_status_valid(
	enum pqcp_deployment_assurance_passport_status status)
{
	return status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_FAIL ||
	       status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARN ||
	       status == PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS;
}

static bool profile_valid(enum pqcp_deployment_release_gate_profile profile)
{
	return profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PROTOTYPE ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PAPER ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PRODUCT ||
	       profile == PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
}

static bool digest_valid(const char *digest)
{
	return pqcp_deployment_evidence_codec_is_lower_hex(
		digest, PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_DIGEST_HEX_CHARS);
}

static bool text_valid(const char *text, size_t capacity)
{
	return text != NULL && text[0] != '\0' &&
	       strnlen(text, capacity) < capacity;
}

static void copy_text(char *destination, size_t capacity, const char *source)
{
	if (destination == NULL || capacity == 0U) {
		return;
	}
	if (source == NULL) {
		destination[0] = '\0';
		return;
	}
	(void)snprintk(destination, capacity, "%s", source);
}

static enum pqcp_deployment_evidence_capsule_error codec_to_capsule_error(
	enum pqcp_deployment_evidence_codec_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_OVERFLOW:
		return PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BUFFER_TOO_SMALL;
	case PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK:
		return PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_NONE;
	default:
		return PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_CODEC;
	}
}

static void capsule_fail(
	struct pqcp_deployment_evidence_capsule *capsule,
	enum pqcp_deployment_evidence_capsule_error error)
{
	if (capsule == NULL) {
		return;
	}
	capsule->status = PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FAIL;
	if (capsule->first_error ==
	    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_NONE) {
		capsule->first_error = error;
	}
}

static bool passport_shape_valid(
	const struct pqcp_deployment_assurance_passport *passport)
{
	if (passport == NULL ||
	    passport->schema_version !=
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_SCHEMA_VERSION ||
	    !passport_status_valid(passport->status) ||
	    !profile_valid(passport->profile) ||
	    passport->passport_score > 100U ||
	    passport->min_terminal_score > 100U ||
	    passport->capability_readiness_score > 100U ||
	    (passport->error_mask &
	     ~PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_KNOWN_MASK) != 0U ||
	    (passport->warning_mask &
	     ~PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_KNOWN_MASK) != 0U) {
		return false;
	}
	if (!text_valid(passport->pqcp_version,
			sizeof(passport->pqcp_version)) ||
	    !text_valid(passport->zephyr_version,
			sizeof(passport->zephyr_version)) ||
	    !text_valid(passport->board, sizeof(passport->board)) ||
	    !text_valid(passport->top_candidate_id,
			sizeof(passport->top_candidate_id)) ||
	    !pqcp_deployment_evidence_codec_is_lower_hex(
		    passport->nonce_hex,
		    PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS) ||
	    !digest_valid(passport->seal_digest_hex) ||
	    !digest_valid(passport->seal_audit_digest_hex) ||
	    !digest_valid(passport->passport_digest_hex)) {
		return false;
	}
	return true;
}

static bool replay_shape_valid(
	const struct pqcp_deployment_assurance_passport_replay_result *replay,
	const struct pqcp_deployment_assurance_passport *passport)
{
	if (replay == NULL || passport == NULL ||
	    replay->schema_version !=
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_SCHEMA_VERSION ||
	    replay->first_error !=
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_NONE ||
	    !replay->passed ||
	    replay->passport_status != passport->status ||
	    replay->passport_error_mask != passport->error_mask ||
	    replay->passport_warning_mask != passport->warning_mask ||
	    replay->profile != passport->profile ||
	    replay->passport_score != passport->passport_score ||
	    replay->min_terminal_score != passport->min_terminal_score ||
	    replay->evidence_capabilities_all !=
		    passport->evidence_capabilities_all ||
	    replay->evidence_capabilities_any !=
		    passport->evidence_capabilities_any ||
	    strcmp(replay->board, passport->board) != 0 ||
	    strcmp(replay->top_candidate_id,
		   passport->top_candidate_id) != 0 ||
	    strcmp(replay->nonce_hex, passport->nonce_hex) != 0 ||
	    strcmp(replay->computed_digest_hex,
		   passport->passport_digest_hex) != 0) {
		return false;
	}
	return true;
}

static bool signature_shape_valid(
	const struct pqcp_deployment_passport_signature *signature,
	const struct pqcp_deployment_assurance_passport *passport)
{
	if (signature == NULL) {
		return true;
	}
#if !defined(CONFIG_PQCP_DEPLOYMENT_PASSPORT_SIGNATURE)
	ARG_UNUSED(passport);
	return false;
#else
	if (signature->schema_version !=
		    PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_SCHEMA_VERSION ||
	    signature->mldsa_level != 65U ||
	    signature->public_key_bytes != PQCP_MLDSA_65_PK_SIZE ||
	    signature->signature_bytes != PQCP_MLDSA_65_SIG_SIZE ||
	    strcmp(signature->passport_digest_hex,
		   passport->passport_digest_hex) != 0) {
		return false;
	}
	return pqcp_deployment_passport_signature_verify(passport,
							 signature) == 0;
#endif
}

static int write_header(
	struct pqcp_deployment_evidence_codec_writer *writer)
{
	int ret;

	ret = pqcp_deployment_evidence_codec_write_u32(
		writer, PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAGIC);
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(
			writer,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_SCHEMA_VERSION);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(writer, 0U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(
			writer, PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(writer, 0U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(writer, 0U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(
			writer, CAPSULE_FORMAT_VERSION);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(writer, 0U);
	}
	return ret;
}

static int begin_record(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint16_t type,
	struct pqcp_deployment_evidence_codec_record_scope *scope,
	uint32_t *record_count)
{
	if (record_count == NULL ||
	    *record_count >= PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_RECORDS) {
		return -E2BIG;
	}
	const int ret = pqcp_deployment_evidence_codec_begin_record(
		writer, type, 0U, scope);

	if (ret == 0) {
		(*record_count)++;
	}
	return ret;
}

static int write_passport_core(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_deployment_assurance_passport *passport,
	uint32_t *record_count)
{
	struct pqcp_deployment_evidence_codec_record_scope scope;
	int ret = begin_record(
		writer,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_CORE,
		&scope, record_count);

#define WRITE_U32(value) \
	do { \
		if (ret == 0) { \
			ret = pqcp_deployment_evidence_codec_write_u32( \
				writer, (uint32_t)(value)); \
		} \
	} while (false)
#define WRITE_BOOL(value) \
	do { \
		if (ret == 0) { \
			ret = pqcp_deployment_evidence_codec_write_bool( \
				writer, (value)); \
		} \
	} while (false)

	WRITE_U32(passport->schema_version);
	WRITE_U32(passport->status);
	WRITE_U32(passport->error_mask);
	WRITE_U32(passport->warning_mask);
	WRITE_U32(passport->profile);
	WRITE_U32(passport->passport_score);
	WRITE_U32(passport->min_terminal_score);
	WRITE_U32(passport->capability_readiness_score);
	WRITE_U32(passport->seal_status);
	WRITE_U32(passport->seal_audit_status);
	WRITE_U32(passport->audited_result_count);
	WRITE_U32(passport->chain_stage_count);
	WRITE_U32(passport->evidence_capabilities_all);
	WRITE_U32(passport->evidence_capabilities_any);
	WRITE_U32(passport->mlkem_level_mask);
	WRITE_U32(passport->mldsa_level_mask);
	WRITE_BOOL(passport->seal_replay_passed);
	WRITE_BOOL(passport->top_consistent);
	WRITE_BOOL(passport->nonce_consistent);
	WRITE_BOOL(passport->seal_digest_consistent);
	WRITE_BOOL(passport->profile_consistent);
	WRITE_BOOL(passport->production_allowed);
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u16(writer, 0U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_end_record(writer,
							       &scope);
	}
#undef WRITE_U32
#undef WRITE_BOOL
	return ret;
}

static int write_passport_identity(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_deployment_assurance_passport *passport,
	uint32_t *record_count)
{
	struct pqcp_deployment_evidence_codec_record_scope scope;
	int ret = begin_record(
		writer,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_IDENTITY,
		&scope, record_count);

	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_text(
			writer, passport->pqcp_version,
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS - 1U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_text(
			writer, passport->zephyr_version,
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS - 1U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_text(
			writer, passport->board,
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS - 1U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_text(
			writer, passport->top_candidate_id,
			PQCP_DEPLOYMENT_ID_MAX_CHARS - 1U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_text(
			writer, passport->nonce_hex,
			PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_end_record(writer,
							       &scope);
	}
	return ret;
}

static int write_passport_digests(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_deployment_assurance_passport *passport,
	uint32_t *record_count)
{
	struct pqcp_deployment_evidence_codec_record_scope scope;
	uint8_t digest[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES];
	int ret = begin_record(
		writer,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_DIGESTS,
		&scope, record_count);

	const char *values[] = {
		passport->seal_digest_hex,
		passport->seal_audit_digest_hex,
		passport->passport_digest_hex,
	};
	for (size_t index = 0U; ret == 0 &&
	     index < sizeof(values) / sizeof(values[0]); ++index) {
		ret = pqcp_deployment_evidence_codec_hex_to_bytes(
			values[index],
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS,
			digest, sizeof(digest));
		if (ret == 0) {
			ret = pqcp_deployment_evidence_codec_write_bytes(
				writer, digest, sizeof(digest));
		}
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_end_record(writer,
							       &scope);
	}
	return ret;
}

static int write_replay(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_deployment_assurance_passport_replay_result *replay,
	uint32_t *record_count)
{
	struct pqcp_deployment_evidence_codec_record_scope scope;
	uint8_t digest[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES];
	int ret = begin_record(
		writer, PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_REPLAY,
		&scope, record_count);

#define WRITE_REPLAY_U32(value) \
	do { \
		if (ret == 0) { \
			ret = pqcp_deployment_evidence_codec_write_u32( \
				writer, (uint32_t)(value)); \
		} \
	} while (false)
	WRITE_REPLAY_U32(replay->schema_version);
	WRITE_REPLAY_U32(replay->first_error);
	WRITE_REPLAY_U32(replay->passport_status);
	WRITE_REPLAY_U32(replay->passport_error_mask);
	WRITE_REPLAY_U32(replay->passport_warning_mask);
	WRITE_REPLAY_U32(replay->profile);
	WRITE_REPLAY_U32(replay->passport_score);
	WRITE_REPLAY_U32(replay->min_terminal_score);
	WRITE_REPLAY_U32(replay->evidence_capabilities_all);
	WRITE_REPLAY_U32(replay->evidence_capabilities_any);
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_bool(
			writer, replay->passed);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_zeros(writer, 3U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_hex_to_bytes(
			replay->computed_digest_hex,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS,
			digest, sizeof(digest));
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_bytes(
			writer, digest, sizeof(digest));
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_end_record(writer,
							       &scope);
	}
#undef WRITE_REPLAY_U32
	return ret;
}

static int write_signature_records(
	struct pqcp_deployment_evidence_codec_writer *writer,
	const struct pqcp_deployment_passport_signature *signature,
	uint32_t *record_count)
{
	struct pqcp_deployment_evidence_codec_record_scope scope;
	uint8_t digest[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES];
	int ret;

	if (signature == NULL) {
		return 0;
	}
	ret = begin_record(
		writer,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_SIGNATURE_META,
		&scope, record_count);
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(
			writer, signature->schema_version);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(
			writer, signature->mldsa_level);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(
			writer, signature->public_key_bytes);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_u32(
			writer, signature->signature_bytes);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_bool(
			writer, signature->boot_post_gated);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_zeros(writer, 3U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_hex_to_bytes(
			signature->passport_digest_hex,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS,
			digest, sizeof(digest));
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_bytes(
			writer, digest, sizeof(digest));
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_end_record(writer,
							       &scope);
	}
	if (ret == 0) {
		ret = begin_record(
			writer,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PUBLIC_KEY,
			&scope, record_count);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_bytes(
			writer, signature->public_key,
			signature->public_key_bytes);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_end_record(writer,
							       &scope);
	}
	if (ret == 0) {
		ret = begin_record(
			writer,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_SIGNATURE,
			&scope, record_count);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_bytes(
			writer, signature->signature,
			signature->signature_bytes);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_end_record(writer,
							       &scope);
	}
	return ret;
}

static uint32_t capsule_flags(
	const struct pqcp_deployment_assurance_passport *passport,
	const struct pqcp_deployment_assurance_passport_replay_result *replay,
	const struct pqcp_deployment_passport_signature *signature)
{
	uint32_t flags = 0U;

	if (signature != NULL) {
		flags |= PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_SIGNED;
		if (signature->boot_post_gated) {
			flags |=
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_BOOT_POST_GATED;
		}
	}
	if (replay->passed) {
		flags |= PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_REPLAY_PASSED;
	}
	if (passport->production_allowed) {
		flags |= PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PRODUCTION;
	}
	if (passport->status ==
	    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS) {
		flags |= PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PASSPORT_PASS;
	}
	return flags;
}

static int append_capsule_digest(
	struct pqcp_deployment_evidence_codec_writer *writer,
	uint32_t *record_count,
	char digest_hex[
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_codec_record_scope scope;
	uint8_t digest_bytes[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES];
	int ret = pqcp_deployment_evidence_digest_buffer_hex(
		CAPSULE_DOMAIN, writer->buffer, writer->offset, digest_hex);

	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_hex_to_bytes(
			digest_hex,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS,
			digest_bytes, sizeof(digest_bytes));
	}
	if (ret == 0) {
		ret = begin_record(
			writer,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_DIGEST,
			&scope, record_count);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_write_bytes(
			writer, digest_bytes, sizeof(digest_bytes));
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_end_record(writer,
							       &scope);
	}
	return ret;
}

const char *pqcp_deployment_evidence_capsule_status_str(
	enum pqcp_deployment_evidence_capsule_status status)
{
	switch (status) {
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_PASS:
		return "PASS";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_WARN:
		return "WARN";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FAIL:
	default:
		return "FAIL";
	}
}

const char *pqcp_deployment_evidence_capsule_error_str(
	enum pqcp_deployment_evidence_capsule_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_PASSPORT:
		return "bad_passport";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_REPLAY:
		return "bad_replay";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_SIGNATURE:
		return "bad_signature";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BUFFER_TOO_SMALL:
		return "buffer_too_small";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_CODEC:
		return "codec";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_RECORD_LIMIT:
		return "record_limit";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_DIGEST:
		return "digest";
	default:
		return "unknown";
	}
}

size_t pqcp_deployment_evidence_capsule_required_bytes(
	bool include_signature)
{
	size_t size = PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES;

	size += 8U + 72U;
	size += 8U + 2U * 5U +
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS * 3U +
		PQCP_DEPLOYMENT_ID_MAX_CHARS +
		PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS;
	size += 8U + PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES * 3U;
	size += 8U + 76U;
	if (include_signature) {
		size += 8U + 52U;
		size += 8U + PQCP_MLDSA_65_PK_SIZE;
		size += 8U + PQCP_MLDSA_65_SIG_SIZE;
	}
	size += 8U + PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES;
	return (size + 3U) & ~(size_t)3U;
}

int pqcp_deployment_evidence_capsule_build(
	const struct pqcp_deployment_assurance_passport *passport,
	const struct pqcp_deployment_assurance_passport_replay_result *replay,
	const struct pqcp_deployment_passport_signature *signature,
	uint8_t *buffer,
	size_t capacity,
	struct pqcp_deployment_evidence_capsule *capsule)
{
	struct pqcp_deployment_evidence_codec_writer writer;
	uint32_t record_count = 0U;
	uint32_t flags;
	size_t digest_record_bytes =
		PQCP_DEPLOYMENT_EVIDENCE_CODEC_RECORD_HEADER_BYTES +
		PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES;
	size_t expected_total;
	int ret;

	if (capsule == NULL) {
		return -EINVAL;
	}
	memset(capsule, 0, sizeof(*capsule));
	capsule->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_SCHEMA_VERSION;
	capsule->status = PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FAIL;
	capsule->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_NONE;
	if (passport == NULL || replay == NULL || buffer == NULL ||
	    capacity == 0U ||
	    capacity > PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES) {
		capsule_fail(
			capsule,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_INVALID_ARGUMENT);
		return -EINVAL;
	}
	if (!passport_shape_valid(passport)) {
		capsule_fail(
			capsule,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_PASSPORT);
		return -EBADMSG;
	}
	if (!replay_shape_valid(replay, passport)) {
		capsule_fail(
			capsule,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_REPLAY);
		return -EBADMSG;
	}
	if (!signature_shape_valid(signature, passport)) {
		capsule_fail(
			capsule,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BAD_SIGNATURE);
		return -EBADMSG;
	}
	if (capacity <
	    pqcp_deployment_evidence_capsule_required_bytes(
		    signature != NULL)) {
		capsule_fail(
			capsule,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BUFFER_TOO_SMALL);
		return -ENOSPC;
	}
	memset(buffer, 0, capacity);
	pqcp_deployment_evidence_codec_writer_init(
		&writer, buffer, capacity);
	ret = write_header(&writer);
	if (ret == 0) {
		ret = write_passport_core(&writer, passport, &record_count);
	}
	if (ret == 0) {
		ret = write_passport_identity(
			&writer, passport, &record_count);
	}
	if (ret == 0) {
		ret = write_passport_digests(
			&writer, passport, &record_count);
	}
	if (ret == 0) {
		ret = write_replay(&writer, replay, &record_count);
	}
	if (ret == 0) {
		ret = write_signature_records(
			&writer, signature, &record_count);
	}
	if (ret != 0) {
		capsule_fail(
			capsule,
			codec_to_capsule_error(writer.error));
		return ret;
	}
	if (record_count + 1U >
	    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_RECORDS) {
		capsule_fail(
			capsule,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_RECORD_LIMIT);
		return -E2BIG;
	}
	expected_total = writer.offset + digest_record_bytes;
	expected_total = (expected_total + 3U) & ~(size_t)3U;
	if (expected_total > UINT32_MAX || expected_total > capacity) {
		capsule_fail(
			capsule,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BUFFER_TOO_SMALL);
		return -ENOSPC;
	}
	flags = capsule_flags(passport, replay, signature);
	ret = pqcp_deployment_evidence_codec_patch_u32(
		&writer, CAPSULE_HEADER_FLAGS_OFFSET, flags);
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_patch_u32(
			&writer, CAPSULE_HEADER_RECORD_COUNT_OFFSET,
			record_count + 1U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_patch_u32(
			&writer, CAPSULE_HEADER_TOTAL_BYTES_OFFSET,
			(uint32_t)expected_total);
	}
	if (ret == 0) {
		ret = append_capsule_digest(
			&writer, &record_count,
			capsule->capsule_digest_hex);
	}
	if (ret != 0 || writer.offset != expected_total) {
		capsule_fail(
			capsule,
			ret == -ENOSPC ?
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_BUFFER_TOO_SMALL :
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_ERROR_DIGEST);
		return ret != 0 ? ret : -EBADMSG;
	}
	capsule->flags = flags;
	capsule->record_count = record_count;
	capsule->byte_count = (uint32_t)writer.offset;
	capsule->passport_score = passport->passport_score;
	capsule->passport_status = passport->status;
	capsule->profile = passport->profile;
	capsule->replay_passed = replay->passed;
	capsule->signature_present = signature != NULL;
	capsule->signature_verified = signature != NULL;
	capsule->production_allowed = passport->production_allowed;
	copy_text(capsule->board, sizeof(capsule->board),
		  passport->board);
	copy_text(capsule->top_candidate_id,
		  sizeof(capsule->top_candidate_id),
		  passport->top_candidate_id);
	copy_text(capsule->nonce_hex, sizeof(capsule->nonce_hex),
		  passport->nonce_hex);
	copy_text(capsule->passport_digest_hex,
		  sizeof(capsule->passport_digest_hex),
		  passport->passport_digest_hex);
	capsule->status =
		passport->status ==
				PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS &&
			(signature == NULL || capsule->signature_verified) ?
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_PASS :
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_WARN;
	return 0;
}

int pqcp_deployment_evidence_capsule_emit(
	const struct pqcp_deployment_evidence_capsule *capsule)
{
	if (capsule == NULL ||
	    capsule->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_SCHEMA_VERSION ||
	    capsule->record_count == 0U ||
	    capsule->record_count >
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_RECORDS ||
	    capsule->byte_count <
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES ||
	    capsule->byte_count >
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES ||
	    !digest_valid(capsule->passport_digest_hex) ||
	    !pqcp_deployment_evidence_codec_is_lower_hex(
		    capsule->capsule_digest_hex,
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS)) {
		return -EINVAL;
	}
	printk("PQCP_DEPLOYMENT_EVIDENCE_CAPSULE schema=%u status=%s "
	       "error=%s flags=0x%08x records=%u bytes=%u profile=%u "
	       "passport_status=%u score=%u replay=%u signed=%u "
	       "signature_verified=%u production=%u board=%s top=%s "
	       "nonce=%s passport_digest=%s capsule_digest=%s\n",
	       capsule->schema_version,
	       pqcp_deployment_evidence_capsule_status_str(capsule->status),
	       pqcp_deployment_evidence_capsule_error_str(
		       capsule->first_error),
	       capsule->flags, capsule->record_count, capsule->byte_count,
	       (uint32_t)capsule->profile,
	       (uint32_t)capsule->passport_status,
	       capsule->passport_score,
	       capsule->replay_passed ? 1U : 0U,
	       capsule->signature_present ? 1U : 0U,
	       capsule->signature_verified ? 1U : 0U,
	       capsule->production_allowed ? 1U : 0U,
	       capsule->board, capsule->top_candidate_id,
	       capsule->nonce_hex, capsule->passport_digest_hex,
	       capsule->capsule_digest_hex);
	return 0;
}
