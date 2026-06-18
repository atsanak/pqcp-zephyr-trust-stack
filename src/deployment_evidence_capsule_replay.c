/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Firmware deployment evidence capsule decoder and replay verifier.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/deployment_evidence_capsule_replay.h>

#define CAPSULE_DOMAIN UINT64_C(0x5051435043415053)
#define CAPSULE_FORMAT_VERSION 1U
#define CAPSULE_REQUIRED_UNSIGNED_MASK \
	((1U << PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_CORE) | \
	 (1U << PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_IDENTITY) | \
	 (1U << PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_DIGESTS) | \
	 (1U << PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_REPLAY))
#define CAPSULE_REQUIRED_SIGNED_MASK \
	(CAPSULE_REQUIRED_UNSIGNED_MASK | \
	 (1U << PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_SIGNATURE_META) | \
	 (1U << PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PUBLIC_KEY) | \
	 (1U << PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_SIGNATURE))

struct capsule_header {
	uint32_t magic;
	uint32_t schema_version;
	uint32_t flags;
	uint32_t header_bytes;
	uint32_t record_count;
	uint32_t total_bytes;
	uint32_t format_version;
	uint32_t reserved;
};

static void set_text(char *destination, size_t capacity, const char *source)
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

static void replay_fail(
	struct pqcp_deployment_evidence_capsule_replay_result *result,
	enum pqcp_deployment_evidence_capsule_replay_error error)
{
	if (result == NULL) {
		return;
	}
	result->passed = false;
	if (result->first_error ==
	    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_NONE) {
		result->first_error = error;
	}
}

static int fail_with(
	struct pqcp_deployment_evidence_capsule_replay_result *result,
	enum pqcp_deployment_evidence_capsule_replay_error error,
	int return_code)
{
	replay_fail(result, error);
	return return_code;
}

static bool record_type_known(uint16_t type)
{
	return type >=
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_CORE &&
	       type <=
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_SIGNATURE;
}

static uint32_t record_bit(uint16_t type)
{
	return type < 32U ? (1U << type) : 0U;
}

static bool passport_status_valid(uint32_t status)
{
	return status <=
	       (uint32_t)PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS;
}

static bool seal_status_valid(uint32_t status)
{
	return status <= (uint32_t)PQCP_DEPLOYMENT_EVIDENCE_SEAL_PASS;
}

static bool seal_audit_status_valid(uint32_t status)
{
	return status <=
	       (uint32_t)PQCP_DEPLOYMENT_EVIDENCE_SEAL_AUDIT_PASS;
}

static bool profile_valid(uint32_t profile)
{
	return profile <=
	       (uint32_t)PQCP_DEPLOYMENT_RELEASE_GATE_PROFILE_PARTNER;
}

static int read_header(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct capsule_header *header,
	struct pqcp_deployment_evidence_capsule_replay_result *result)
{
	int ret;

	if (reader == NULL || header == NULL || result == NULL) {
		return -EINVAL;
	}
	memset(header, 0, sizeof(*header));
#define READ_HEADER_U32(field) \
	do { \
		ret = pqcp_deployment_evidence_codec_read_u32( \
			reader, &header->field); \
		if (ret != 0) { \
			result->codec_error = reader->error; \
			return fail_with( \
				result, \
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_HEADER, \
				ret); \
		} \
	} while (false)
	READ_HEADER_U32(magic);
	READ_HEADER_U32(schema_version);
	READ_HEADER_U32(flags);
	READ_HEADER_U32(header_bytes);
	READ_HEADER_U32(record_count);
	READ_HEADER_U32(total_bytes);
	READ_HEADER_U32(format_version);
	READ_HEADER_U32(reserved);
#undef READ_HEADER_U32
	if (header->magic != PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAGIC ||
	    header->header_bytes !=
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES ||
	    header->format_version != CAPSULE_FORMAT_VERSION ||
	    header->reserved != 0U) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_HEADER,
			-EBADMSG);
	}
	if (header->schema_version !=
	    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_SCHEMA_VERSION) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_SCHEMA,
			-EPROTONOSUPPORT);
	}
	if ((header->flags &
	     ~PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_KNOWN_MASK) != 0U) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_FLAGS,
			-EBADMSG);
	}
	if (header->record_count == 0U ||
	    header->record_count >
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_RECORDS ||
	    header->total_bytes != reader->length ||
	    header->total_bytes <
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES ||
	    header->total_bytes >
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_LENGTH,
			-EMSGSIZE);
	}
	result->flags = header->flags;
	result->records_expected = header->record_count;
	return 0;
}

static int read_reserved_zeros(
	struct pqcp_deployment_evidence_codec_reader *reader,
	size_t count)
{
	uint8_t value;
	int ret;

	for (size_t index = 0U; index < count; ++index) {
		ret = pqcp_deployment_evidence_codec_read_u8(reader, &value);
		if (ret != 0) {
			return ret;
		}
		if (value != 0U) {
			reader->error =
				PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED;
			return -EBADMSG;
		}
	}
	return 0;
}

static int read_passport_core(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_deployment_assurance_passport *passport)
{
	uint32_t values[16];
	bool bool_values[6];
	uint16_t reserved;
	int ret = 0;

	for (size_t index = 0U;
	     ret == 0 && index < sizeof(values) / sizeof(values[0]);
	     ++index) {
		ret = pqcp_deployment_evidence_codec_read_u32(
			reader, &values[index]);
	}
	for (size_t index = 0U;
	     ret == 0 && index < sizeof(bool_values) / sizeof(bool_values[0]);
	     ++index) {
		ret = pqcp_deployment_evidence_codec_read_bool(
			reader, &bool_values[index]);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_u16(
			reader, &reserved);
	}
	if (ret != 0) {
		return ret;
	}
	if (reserved != 0U ||
	    values[0] !=
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_SCHEMA_VERSION ||
	    !passport_status_valid(values[1]) ||
	    !profile_valid(values[4]) ||
	    values[5] > 100U || values[6] > 100U || values[7] > 100U ||
	    !seal_status_valid(values[8]) ||
	    !seal_audit_status_valid(values[9]) ||
	    (values[2] &
	     ~PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_ERROR_KNOWN_MASK) != 0U ||
	    (values[3] &
	     ~PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_WARNING_KNOWN_MASK) != 0U) {
		reader->error = PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED;
		return -EBADMSG;
	}
	passport->schema_version = values[0];
	passport->status =
		(enum pqcp_deployment_assurance_passport_status)values[1];
	passport->error_mask = values[2];
	passport->warning_mask = values[3];
	passport->profile =
		(enum pqcp_deployment_release_gate_profile)values[4];
	passport->passport_score = values[5];
	passport->min_terminal_score = values[6];
	passport->capability_readiness_score = values[7];
	passport->seal_status =
		(enum pqcp_deployment_evidence_seal_status)values[8];
	passport->seal_audit_status =
		(enum pqcp_deployment_evidence_seal_audit_status)values[9];
	passport->audited_result_count = values[10];
	passport->chain_stage_count = values[11];
	passport->evidence_capabilities_all = values[12];
	passport->evidence_capabilities_any = values[13];
	passport->mlkem_level_mask = values[14];
	passport->mldsa_level_mask = values[15];
	passport->seal_replay_passed = bool_values[0];
	passport->top_consistent = bool_values[1];
	passport->nonce_consistent = bool_values[2];
	passport->seal_digest_consistent = bool_values[3];
	passport->profile_consistent = bool_values[4];
	passport->production_allowed = bool_values[5];
	return 0;
}

static int read_passport_identity(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_deployment_assurance_passport *passport)
{
	int ret = pqcp_deployment_evidence_codec_read_text(
		reader, passport->pqcp_version,
		sizeof(passport->pqcp_version),
		PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS - 1U);

	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_text(
			reader, passport->zephyr_version,
			sizeof(passport->zephyr_version),
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS - 1U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_text(
			reader, passport->board,
			sizeof(passport->board),
			PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_TEXT_MAX_CHARS - 1U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_text(
			reader, passport->top_candidate_id,
			sizeof(passport->top_candidate_id),
			PQCP_DEPLOYMENT_ID_MAX_CHARS - 1U);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_text(
			reader, passport->nonce_hex,
			sizeof(passport->nonce_hex),
			PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS);
	}
	if (ret == 0 &&
	    (!pqcp_deployment_evidence_codec_is_lower_hex(
		     passport->nonce_hex,
		     PQCP_DEPLOYMENT_DEVICE_TOKEN_NONCE_HEX_CHARS) ||
	     passport->pqcp_version[0] == '\0' ||
	     passport->zephyr_version[0] == '\0' ||
	     passport->board[0] == '\0' ||
	     passport->top_candidate_id[0] == '\0')) {
		reader->error = PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED;
		return -EBADMSG;
	}
	return ret;
}

static int read_digest_hex(
	struct pqcp_deployment_evidence_codec_reader *reader,
	char output[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U])
{
	uint8_t bytes[PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_BYTES];
	int ret = pqcp_deployment_evidence_codec_read_bytes(
		reader, bytes, sizeof(bytes));

	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_bytes_to_hex(
			bytes, sizeof(bytes), output,
			PQCP_DEPLOYMENT_EVIDENCE_CODEC_DIGEST_HEX_CHARS + 1U);
	}
	return ret;
}

static int read_passport_digests(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_deployment_assurance_passport *passport)
{
	int ret = read_digest_hex(reader, passport->seal_digest_hex);

	if (ret == 0) {
		ret = read_digest_hex(reader,
				      passport->seal_audit_digest_hex);
	}
	if (ret == 0) {
		ret = read_digest_hex(reader,
				      passport->passport_digest_hex);
	}
	return ret;
}

static int read_replay(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_deployment_assurance_passport_replay_result *replay)
{
	uint32_t values[10];
	int ret = 0;

	for (size_t index = 0U;
	     ret == 0 && index < sizeof(values) / sizeof(values[0]);
	     ++index) {
		ret = pqcp_deployment_evidence_codec_read_u32(
			reader, &values[index]);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_bool(
			reader, &replay->passed);
	}
	if (ret == 0) {
		ret = read_reserved_zeros(reader, 3U);
	}
	if (ret == 0) {
		ret = read_digest_hex(reader,
				      replay->computed_digest_hex);
	}
	if (ret != 0) {
		return ret;
	}
	if (values[0] !=
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_SCHEMA_VERSION ||
	    values[1] >
		    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_REPLAY_ERROR_SCORE_RANGE ||
	    !passport_status_valid(values[2]) ||
	    !profile_valid(values[5]) ||
	    values[6] > 100U || values[7] > 100U) {
		reader->error = PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED;
		return -EBADMSG;
	}
	replay->schema_version = values[0];
	replay->first_error =
		(enum pqcp_deployment_assurance_passport_replay_error)values[1];
	replay->passport_status =
		(enum pqcp_deployment_assurance_passport_status)values[2];
	replay->passport_error_mask = values[3];
	replay->passport_warning_mask = values[4];
	replay->profile =
		(enum pqcp_deployment_release_gate_profile)values[5];
	replay->passport_score = values[6];
	replay->min_terminal_score = values[7];
	replay->evidence_capabilities_all = values[8];
	replay->evidence_capabilities_any = values[9];
	return 0;
}

static int read_signature_meta(
	struct pqcp_deployment_evidence_codec_reader *reader,
	struct pqcp_deployment_passport_signature *signature)
{
	int ret;

	ret = pqcp_deployment_evidence_codec_read_u32(
		reader, &signature->schema_version);
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_u32(
			reader, &signature->mldsa_level);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_u32(
			reader, &signature->public_key_bytes);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_u32(
			reader, &signature->signature_bytes);
	}
	if (ret == 0) {
		ret = pqcp_deployment_evidence_codec_read_bool(
			reader, &signature->boot_post_gated);
	}
	if (ret == 0) {
		ret = read_reserved_zeros(reader, 3U);
	}
	if (ret == 0) {
		ret = read_digest_hex(reader,
				      signature->passport_digest_hex);
	}
	if (ret != 0) {
		return ret;
	}
	if (signature->schema_version !=
		    PQCP_DEPLOYMENT_PASSPORT_SIGNATURE_SCHEMA_VERSION ||
	    signature->mldsa_level != 65U ||
	    signature->public_key_bytes != PQCP_MLDSA_65_PK_SIZE ||
	    signature->signature_bytes != PQCP_MLDSA_65_SIG_SIZE) {
		reader->error = PQCP_DEPLOYMENT_EVIDENCE_CODEC_MALFORMED;
		return -EBADMSG;
	}
	return 0;
}

static int verify_decoded_replay(
	struct pqcp_deployment_evidence_capsule_replay_workspace *workspace,
	struct pqcp_deployment_evidence_capsule_replay_result *result)
{
	struct pqcp_deployment_assurance_passport_replay_result recomputed;
	int ret = pqcp_deployment_assurance_passport_replay_verify(
		&workspace->passport, &recomputed);

	if (ret != 0 || !recomputed.passed ||
	    memcmp(&recomputed, &workspace->replay,
		   sizeof(recomputed)) != 0) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_PASSPORT_REPLAY,
			-EBADMSG);
	}
	result->passport_replayed = true;
	return 0;
}

static int verify_signature(
	struct pqcp_deployment_evidence_capsule_replay_workspace *workspace,
	bool signature_present,
	struct pqcp_deployment_evidence_capsule_replay_result *result)
{
	if (!signature_present) {
		result->signature_present = false;
		result->signature_verified = false;
		return 0;
	}
	result->signature_present = true;
#if !defined(CONFIG_PQCP_DEPLOYMENT_PASSPORT_SIGNATURE)
	ARG_UNUSED(workspace);
	return fail_with(
		result,
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_SIGNATURE,
		-ENOTSUP);
#else
	if (strcmp(workspace->signature.passport_digest_hex,
		   workspace->passport.passport_digest_hex) != 0 ||
	    pqcp_deployment_passport_signature_verify(
		    &workspace->passport, &workspace->signature) != 0) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_SIGNATURE,
			-EBADMSG);
	}
	result->signature_verified = true;
	return 0;
#endif
}

static int verify_flags(
	const struct pqcp_deployment_evidence_capsule_replay_workspace *workspace,
	const struct pqcp_deployment_evidence_capsule_replay_result *result,
	bool signature_present)
{
	uint32_t expected = 0U;

	if (signature_present) {
		expected |= PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_SIGNED;
		if (workspace->signature.boot_post_gated) {
			expected |=
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_BOOT_POST_GATED;
		}
	}
	if (workspace->replay.passed) {
		expected |=
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_REPLAY_PASSED;
	}
	if (workspace->passport.production_allowed) {
		expected |=
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PRODUCTION;
	}
	if (workspace->passport.status ==
	    PQCP_DEPLOYMENT_ASSURANCE_PASSPORT_PASS) {
		expected |=
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_PASSPORT_PASS;
	}
	return expected == result->flags ? 0 : -EBADMSG;
}

const char *pqcp_deployment_evidence_capsule_replay_error_str(
	enum pqcp_deployment_evidence_capsule_replay_error error)
{
	switch (error) {
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_NONE:
		return "none";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_INVALID_ARGUMENT:
		return "invalid_argument";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_HEADER:
		return "bad_header";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_SCHEMA:
		return "bad_schema";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_FLAGS:
		return "bad_flags";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_BAD_LENGTH:
		return "bad_length";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_RECORD_ORDER:
		return "record_order";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DUPLICATE_RECORD:
		return "duplicate_record";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MISSING_RECORD:
		return "missing_record";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MALFORMED_RECORD:
		return "malformed_record";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DIGEST_MISMATCH:
		return "digest_mismatch";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_PASSPORT_REPLAY:
		return "passport_replay";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_SIGNATURE:
		return "signature";
	case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_FLAG_MISMATCH:
		return "flag_mismatch";
	default:
		return "unknown";
	}
}

int pqcp_deployment_evidence_capsule_replay_verify(
	const uint8_t *buffer,
	size_t length,
	struct pqcp_deployment_evidence_capsule_replay_workspace *workspace,
	struct pqcp_deployment_evidence_capsule_replay_result *result)
{
	struct pqcp_deployment_evidence_codec_reader reader;
	struct pqcp_deployment_evidence_codec_reader payload;
	struct pqcp_deployment_evidence_codec_record record;
	struct capsule_header header;
	char observed_digest[
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS + 1U] = {0};
	char computed_digest[
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_DIGEST_HEX_CHARS + 1U] = {0};
	uint32_t expected_mask;
	uint16_t last_type = 0U;
	bool signature_present;
	bool saw_digest = false;
	int ret;

	if (result == NULL) {
		return -EINVAL;
	}
	memset(result, 0, sizeof(*result));
	result->schema_version =
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_SCHEMA_VERSION;
	result->first_error =
		PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_NONE;
	result->codec_error = PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK;
	if (buffer == NULL || workspace == NULL ||
	    length < PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_HEADER_BYTES ||
	    length > PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_BYTES) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_INVALID_ARGUMENT,
			-EINVAL);
	}
	memset(workspace, 0, sizeof(*workspace));
	pqcp_deployment_evidence_codec_reader_init(&reader, buffer, length);
	ret = read_header(&reader, &header, result);
	if (ret != 0) {
		return ret;
	}
	while (result->records_seen < header.record_count) {
		ret = pqcp_deployment_evidence_codec_next_record(
			&reader, &record);
		if (ret != 0) {
			result->codec_error = reader.error;
			return fail_with(
				result,
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MALFORMED_RECORD,
				ret);
		}
		result->records_seen++;
		if (record.type ==
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_DIGEST) {
			if (saw_digest ||
			    result->records_seen != header.record_count) {
				return fail_with(
					result,
					saw_digest ?
						PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DUPLICATE_RECORD :
						PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_RECORD_ORDER,
					-EBADMSG);
			}
			ret = pqcp_deployment_evidence_codec_record_reader(
				&reader, &record, &payload);
			if (ret == 0) {
				ret = read_digest_hex(
					&payload, observed_digest);
			}
			if (ret == 0) {
				ret = pqcp_deployment_evidence_codec_finish_record(
					&reader, &record, &payload);
			}
			if (ret != 0) {
				result->codec_error =
					payload.error !=
							PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK ?
						payload.error : reader.error;
				return fail_with(
					result,
					PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MALFORMED_RECORD,
					ret);
			}
			ret = pqcp_deployment_evidence_digest_buffer_hex(
				CAPSULE_DOMAIN, buffer,
				record.header_offset, computed_digest);
			if (ret != 0 ||
			    strcmp(observed_digest, computed_digest) != 0) {
				return fail_with(
					result,
					PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DIGEST_MISMATCH,
					-EBADMSG);
			}
			saw_digest = true;
			result->digest_verified = true;
			continue;
		}
		if (!record_type_known(record.type)) {
			return fail_with(
				result,
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MALFORMED_RECORD,
				-EBADMSG);
		}
		if (record.type <= last_type) {
			return fail_with(
				result,
				record.type == last_type ?
					PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DUPLICATE_RECORD :
					PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_RECORD_ORDER,
				-EBADMSG);
		}
		if ((result->record_mask & record_bit(record.type)) != 0U) {
			return fail_with(
				result,
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_DUPLICATE_RECORD,
				-EBADMSG);
		}
		result->record_mask |= record_bit(record.type);
		last_type = record.type;
		ret = pqcp_deployment_evidence_codec_record_reader(
			&reader, &record, &payload);
		if (ret != 0) {
			return fail_with(
				result,
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MALFORMED_RECORD,
				ret);
		}
		switch (record.type) {
		case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_CORE:
			ret = read_passport_core(
				&payload, &workspace->passport);
			break;
		case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_IDENTITY:
			ret = read_passport_identity(
				&payload, &workspace->passport);
			break;
		case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PASSPORT_DIGESTS:
			ret = read_passport_digests(
				&payload, &workspace->passport);
			break;
		case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_REPLAY:
			ret = read_replay(&payload, &workspace->replay);
			break;
		case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_SIGNATURE_META:
			ret = read_signature_meta(
				&payload, &workspace->signature);
			break;
		case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PUBLIC_KEY:
			ret = pqcp_deployment_evidence_codec_read_bytes(
				&payload, workspace->signature.public_key,
				PQCP_MLDSA_65_PK_SIZE);
			break;
		case PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_SIGNATURE:
			ret = pqcp_deployment_evidence_codec_read_bytes(
				&payload, workspace->signature.signature,
				PQCP_MLDSA_65_SIG_SIZE);
			break;
		default:
			ret = -EBADMSG;
			break;
		}
		if (ret == 0) {
			ret = pqcp_deployment_evidence_codec_finish_record(
				&reader, &record, &payload);
		}
		if (ret != 0) {
			result->codec_error =
				payload.error !=
						PQCP_DEPLOYMENT_EVIDENCE_CODEC_OK ?
					payload.error : reader.error;
			return fail_with(
				result,
				PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MALFORMED_RECORD,
				ret);
		}
	}
	if (!saw_digest ||
	    pqcp_deployment_evidence_codec_require_eof(&reader) != 0) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MISSING_RECORD,
			-EBADMSG);
	}
	signature_present =
		(header.flags &
		 PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_FLAG_SIGNED) != 0U;
	expected_mask = signature_present ?
				CAPSULE_REQUIRED_SIGNED_MASK :
				CAPSULE_REQUIRED_UNSIGNED_MASK;
	if ((result->record_mask & expected_mask) != expected_mask ||
	    (!signature_present &&
	     (result->record_mask &
	      (record_bit(
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_SIGNATURE_META) |
	       record_bit(
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_PUBLIC_KEY) |
	       record_bit(
		       PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_RECORD_SIGNATURE))) !=
		     0U)) {
		return fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_MISSING_RECORD,
			-EBADMSG);
	}
	set_text(workspace->replay.board,
		 sizeof(workspace->replay.board),
		 workspace->passport.board);
	set_text(workspace->replay.top_candidate_id,
		 sizeof(workspace->replay.top_candidate_id),
		 workspace->passport.top_candidate_id);
	set_text(workspace->replay.nonce_hex,
		 sizeof(workspace->replay.nonce_hex),
		 workspace->passport.nonce_hex);
	ret = verify_decoded_replay(workspace, result);
	if (ret == 0) {
		ret = verify_signature(
			workspace, signature_present, result);
	}
	if (ret == 0 &&
	    verify_flags(workspace, result, signature_present) != 0) {
		ret = fail_with(
			result,
			PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_ERROR_FLAG_MISMATCH,
			-EBADMSG);
	}
	if (ret != 0) {
		return ret;
	}
	result->bytes_consumed = header.total_bytes;
	result->passport_status = workspace->passport.status;
	result->profile = workspace->passport.profile;
	result->passport_score = workspace->passport.passport_score;
	result->production_allowed =
		workspace->passport.production_allowed;
	set_text(result->board, sizeof(result->board),
		 workspace->passport.board);
	set_text(result->top_candidate_id,
		 sizeof(result->top_candidate_id),
		 workspace->passport.top_candidate_id);
	set_text(result->nonce_hex, sizeof(result->nonce_hex),
		 workspace->passport.nonce_hex);
	set_text(result->passport_digest_hex,
		 sizeof(result->passport_digest_hex),
		 workspace->passport.passport_digest_hex);
	set_text(result->capsule_digest_hex,
		 sizeof(result->capsule_digest_hex),
		 computed_digest);
	result->passed = true;
	return 0;
}

int pqcp_deployment_evidence_capsule_replay_emit(
	const struct pqcp_deployment_evidence_capsule_replay_result *result)
{
	if (result == NULL ||
	    result->schema_version !=
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY_SCHEMA_VERSION ||
	    result->records_seen > result->records_expected ||
	    result->records_expected >
		    PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_MAX_RECORDS) {
		return -EINVAL;
	}
	printk("PQCP_DEPLOYMENT_EVIDENCE_CAPSULE_REPLAY schema=%u "
	       "status=%s error=%s codec_error=%s flags=0x%08x "
	       "records=%u expected=%u bytes=%u mask=0x%08x "
	       "passport_status=%u profile=%u score=%u passport_replay=%u "
	       "signed=%u signature_verified=%u digest_verified=%u "
	       "production=%u board=%s top=%s nonce=%s "
	       "passport_digest=%s capsule_digest=%s\n",
	       result->schema_version, result->passed ? "PASS" : "FAIL",
	       pqcp_deployment_evidence_capsule_replay_error_str(
		       result->first_error),
	       pqcp_deployment_evidence_codec_error_str(
		       result->codec_error),
	       result->flags, result->records_seen,
	       result->records_expected, result->bytes_consumed,
	       result->record_mask, (uint32_t)result->passport_status,
	       (uint32_t)result->profile, result->passport_score,
	       result->passport_replayed ? 1U : 0U,
	       result->signature_present ? 1U : 0U,
	       result->signature_verified ? 1U : 0U,
	       result->digest_verified ? 1U : 0U,
	       result->production_allowed ? 1U : 0U,
	       result->board, result->top_candidate_id,
	       result->nonce_hex, result->passport_digest_hex,
	       result->capsule_digest_hex);
	return 0;
}
