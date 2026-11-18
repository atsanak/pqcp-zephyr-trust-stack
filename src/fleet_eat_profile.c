/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * RFC 9711 EAT claims profile encoded as a deterministic CWT claims set.
 */

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/fleet_eat.h>

#define EAT_MEASUREMENT_LABEL_SYSTEM 1
#define EAT_MEASUREMENT_LABEL_IDENTIFIER 2
#define EAT_MEASUREMENT_LABEL_RESULT 3
#define EAT_MEASUREMENT_LABEL_DIGEST 4
#define EAT_USER_PRIVATE_LABEL_MAX (-70100)

static size_t text_length(
	const char *value,
	size_t capacity)
{
	size_t length = 0U;

	if (value == NULL) {
		return 0U;
	}
	while (length < capacity && value[length] != '\0') {
		length++;
	}
	return length;
}

static bool text_optional_valid(
	const char *value,
	size_t capacity)
{
	return text_length(value, capacity) < capacity;
}

static bool text_required_valid(
	const char *value,
	size_t capacity)
{
	const size_t length = text_length(value, capacity);

	return length != 0U && length < capacity;
}

static bool digest_length_valid(size_t length)
{
	return length == 0U ||
	       length == PQCP_FLEET_EAT_DIGEST_BYTES;
}

static int measurement_validate(
	const struct pqcp_fleet_eat_measurement *measurement)
{
	if (measurement == NULL ||
	    !text_required_valid(
		    measurement->system,
		    sizeof(measurement->system)) ||
	    !text_required_valid(
		    measurement->identifier,
		    sizeof(measurement->identifier)) ||
	    measurement->result <
		    PQCP_FLEET_EAT_MEASUREMENT_SUCCESS ||
	    measurement->result >
		    PQCP_FLEET_EAT_MEASUREMENT_ABSENT ||
	    !digest_length_valid(measurement->digest_length)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (measurement->result ==
		    PQCP_FLEET_EAT_MEASUREMENT_SUCCESS &&
	    measurement->digest_length == 0U) {
		return PQCP_FLEET_COSE_ERR_REQUIRED;
	}
	return 0;
}

static int private_claim_validate(
	const struct pqcp_fleet_eat_private_claim *claim)
{
	if (claim == NULL ||
	    claim->label > EAT_USER_PRIVATE_LABEL_MAX ||
	    claim->type < PQCP_FLEET_EAT_PRIVATE_UINT ||
	    claim->type > PQCP_FLEET_EAT_PRIVATE_TEXT) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	switch (claim->type) {
	case PQCP_FLEET_EAT_PRIVATE_BYTES:
		if (claim->value.bytes.data == NULL &&
		    claim->value.bytes.length != 0U) {
			return PQCP_FLEET_COSE_ERR_ARGUMENT;
		}
		break;
	case PQCP_FLEET_EAT_PRIVATE_TEXT:
		if (claim->value.text == NULL ||
		    claim->text_length == 0U) {
			return PQCP_FLEET_COSE_ERR_ARGUMENT;
		}
		break;
	default:
		break;
	}
	return 0;
}

static int private_claim_order(
	const struct pqcp_fleet_eat_private_claim *left,
	const struct pqcp_fleet_eat_private_claim *right)
{
	const uint64_t left_argument =
		(uint64_t)(-(left->label + 1));
	const uint64_t right_argument =
		(uint64_t)(-(right->label + 1));

	return left_argument < right_argument ? -1 :
	       left_argument > right_argument ? 1 : 0;
}

int pqcp_fleet_eat_claims_validate(
	const struct pqcp_fleet_eat_claims *claims)
{
	size_t profile_length;
	int ret;

	if (claims == NULL ||
	    claims->role < PQCP_FLEET_EAT_ROLE_EVIDENCE ||
	    claims->role >
		    PQCP_FLEET_EAT_ROLE_ATTESTATION_RESULT ||
	    claims->nonce_length <
		    PQCP_FLEET_EAT_NONCE_MIN_BYTES ||
	    claims->nonce_length >
		    PQCP_FLEET_EAT_NONCE_MAX_BYTES ||
	    claims->ueid_length <
		    PQCP_FLEET_EAT_UEID_MIN_BYTES ||
	    claims->ueid_length >
		    PQCP_FLEET_EAT_UEID_MAX_BYTES ||
	    claims->measurement_count >
		    PQCP_FLEET_EAT_MAX_MEASUREMENTS ||
	    claims->advice_count >
		    PQCP_FLEET_EAT_MAX_ADVICE ||
	    claims->private_claim_count >
		    PQCP_FLEET_EAT_MAX_PRIVATE_CLAIMS ||
	    !text_optional_valid(
		    claims->issuer, sizeof(claims->issuer)) ||
	    !text_optional_valid(
		    claims->subject, sizeof(claims->subject)) ||
	    !text_optional_valid(
		    claims->audience, sizeof(claims->audience)) ||
	    !text_optional_valid(
		    claims->software_name,
		    sizeof(claims->software_name)) ||
	    !text_optional_valid(
		    claims->software_version,
		    sizeof(claims->software_version)) ||
	    !text_optional_valid(
		    claims->hardware_version,
		    sizeof(claims->hardware_version)) ||
	    claims->hardware_model_length >
		    sizeof(claims->hardware_model) ||
	    claims->token_id_length >
		    sizeof(claims->token_id) ||
	    !digest_length_valid(
		    claims->firmware_digest_length) ||
	    !digest_length_valid(
		    claims->policy_digest_length) ||
	    !digest_length_valid(
		    claims->audit_root_length) ||
	    !digest_length_valid(
		    claims->channel_binding_length) ||
	    !digest_length_valid(
		    claims->evidence_digest_length)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	profile_length = text_length(
		claims->profile, sizeof(claims->profile));
	if (profile_length == 0U ||
	    profile_length >= sizeof(claims->profile) ||
	    strcmp(claims->profile,
		   PQCP_FLEET_EAT_PROFILE_URI) != 0) {
		return PQCP_FLEET_COSE_ERR_POLICY;
	}
	if (claims->issued_at_present &&
	    claims->issued_at == 0U) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (claims->expiration_present &&
	    (!claims->issued_at_present ||
	     claims->expiration <= claims->issued_at)) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (claims->not_before_present &&
	    claims->expiration_present &&
	    claims->not_before >= claims->expiration) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (claims->debug_status_present &&
	    claims->debug_status >
		    PQCP_FLEET_EAT_DEBUG_DISABLED_FULLY_AND_PERMANENTLY) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (claims->runtime_state_present &&
	    claims->runtime_state >
		    PQCP_FLEET_EAT_RUNTIME_DECOMMISSIONED) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (claims->appraisal_present &&
	    claims->appraisal >
		    PQCP_FLEET_EAT_APPRAISAL_QUARANTINE) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	if (claims->role ==
		    PQCP_FLEET_EAT_ROLE_ATTESTATION_RESULT &&
	    (!claims->appraisal_present ||
	     claims->evidence_digest_length == 0U)) {
		return PQCP_FLEET_COSE_ERR_REQUIRED;
	}
	for (size_t index = 0U;
	     index < claims->measurement_count; ++index) {
		ret = measurement_validate(
			&claims->measurements[index]);
		if (ret != 0) {
			return ret;
		}
	}
	for (size_t index = 0U;
	     index < claims->advice_count; ++index) {
		if (claims->advice[index] <
			    PQCP_FLEET_EAT_ADVICE_ALLOW ||
		    claims->advice[index] >
			    PQCP_FLEET_EAT_ADVICE_REENROLL) {
			return PQCP_FLEET_COSE_ERR_ARGUMENT;
		}
		for (size_t previous = 0U;
		     previous < index; ++previous) {
			if (claims->advice[previous] ==
			    claims->advice[index]) {
				return PQCP_FLEET_COSE_ERR_DUPLICATE;
			}
		}
	}
	for (size_t index = 0U;
	     index < claims->private_claim_count; ++index) {
		ret = private_claim_validate(
			&claims->private_claims[index]);
		if (ret != 0) {
			return ret;
		}
		for (size_t previous = 0U;
		     previous < index; ++previous) {
			if (claims->private_claims[previous].label ==
			    claims->private_claims[index].label) {
				return PQCP_FLEET_COSE_ERR_DUPLICATE;
			}
		}
	}
	return 0;
}

static size_t claims_field_count(
	const struct pqcp_fleet_eat_claims *claims)
{
	size_t count = 5U;

#define COUNT_TEXT(field) \
	do { \
		if (text_length((field), sizeof(field)) != 0U) { \
			count++; \
		} \
	} while (0)
#define COUNT_PRESENT(field) \
	do { \
		if ((field)) { \
			count++; \
		} \
	} while (0)
#define COUNT_LENGTH(field) \
	do { \
		if ((field) != 0U) { \
			count++; \
		} \
	} while (0)

	COUNT_TEXT(claims->issuer);
	COUNT_TEXT(claims->subject);
	COUNT_TEXT(claims->audience);
	COUNT_PRESENT(claims->expiration_present);
	COUNT_PRESENT(claims->not_before_present);
	COUNT_PRESENT(claims->issued_at_present);
	COUNT_LENGTH(claims->token_id_length);
	COUNT_LENGTH(claims->hardware_model_length);
	if (claims->oem_id != 0U) {
		count++;
	}
	COUNT_TEXT(claims->hardware_version);
	COUNT_PRESENT(claims->uptime_present);
	/* oem_boot is written unconditionally and is already part of the
	 * base count; counting it again produced a map head one pair too
	 * large, so no encoded claims map was valid CBOR.
	 */
	COUNT_PRESENT(claims->debug_status_present);
	COUNT_PRESENT(claims->boot_count_present);
	COUNT_TEXT(claims->software_name);
	COUNT_TEXT(claims->software_version);
	if (claims->measurement_count != 0U) {
		count++;
	}
	COUNT_PRESENT(claims->policy_epoch_present);
	COUNT_PRESENT(claims->revocation_epoch_present);
	COUNT_PRESENT(claims->credential_epoch_present);
	COUNT_PRESENT(claims->runtime_state_present);
	COUNT_PRESENT(claims->risk_score_present);
	COUNT_PRESENT(claims->capabilities_present);
	COUNT_LENGTH(claims->firmware_digest_length);
	COUNT_LENGTH(claims->policy_digest_length);
	COUNT_LENGTH(claims->audit_root_length);
	COUNT_LENGTH(claims->channel_binding_length);
	COUNT_PRESENT(claims->appraisal_present);
	COUNT_PRESENT(claims->result_reason_present);
	COUNT_LENGTH(claims->evidence_digest_length);
	COUNT_PRESENT(claims->reference_set_present);
	if (claims->advice_count != 0U) {
		count++;
	}
	count += claims->private_claim_count;

#undef COUNT_TEXT
#undef COUNT_PRESENT
#undef COUNT_LENGTH
	return count;
}

static int write_label(
	struct pqcp_fleet_cbor_writer *writer,
	int64_t label)
{
	return pqcp_fleet_cbor_write_int(writer, label);
}

static int write_text_claim(
	struct pqcp_fleet_cbor_writer *writer,
	int64_t label,
	const char *value,
	size_t capacity)
{
	const size_t length = text_length(value, capacity);
	int ret;

	if (length == 0U) {
		return 0;
	}
	ret = write_label(writer, label);
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_text(
			writer, value, length);
	}
	return ret;
}

static int write_uint_claim(
	struct pqcp_fleet_cbor_writer *writer,
	int64_t label,
	uint64_t value)
{
	int ret = write_label(writer, label);

	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_uint(writer, value);
	}
	return ret;
}

static int write_int_claim(
	struct pqcp_fleet_cbor_writer *writer,
	int64_t label,
	int64_t value)
{
	int ret = write_label(writer, label);

	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_int(writer, value);
	}
	return ret;
}

static int write_bool_claim(
	struct pqcp_fleet_cbor_writer *writer,
	int64_t label,
	bool value)
{
	int ret = write_label(writer, label);

	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_bool(writer, value);
	}
	return ret;
}

static int write_bytes_claim(
	struct pqcp_fleet_cbor_writer *writer,
	int64_t label,
	const uint8_t *value,
	size_t length)
{
	int ret;

	if (length == 0U) {
		return 0;
	}
	ret = write_label(writer, label);
	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_bytes(
			writer, value, length);
	}
	return ret;
}

static int write_measurements(
	struct pqcp_fleet_cbor_writer *writer,
	const struct pqcp_fleet_eat_claims *claims)
{
	int ret = write_label(
		writer, PQCP_FLEET_EAT_CLAIM_MEASUREMENTS);

	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_array(
			writer, claims->measurement_count);
	}
	for (size_t index = 0U;
	     ret == 0 &&
	     index < claims->measurement_count; ++index) {
		const struct pqcp_fleet_eat_measurement *measurement =
			&claims->measurements[index];
		const size_t fields =
			measurement->digest_length != 0U ?
				4U : 3U;

		ret = pqcp_fleet_cbor_write_map(writer, fields);
		if (ret == 0) {
			ret = write_text_claim(
				writer,
				EAT_MEASUREMENT_LABEL_SYSTEM,
				measurement->system,
				sizeof(measurement->system));
		}
		if (ret == 0) {
			ret = write_text_claim(
				writer,
				EAT_MEASUREMENT_LABEL_IDENTIFIER,
				measurement->identifier,
				sizeof(measurement->identifier));
		}
		if (ret == 0) {
			ret = write_int_claim(
				writer,
				EAT_MEASUREMENT_LABEL_RESULT,
				measurement->result);
		}
		if (ret == 0) {
			ret = write_bytes_claim(
				writer,
				EAT_MEASUREMENT_LABEL_DIGEST,
				measurement->digest,
				measurement->digest_length);
		}
	}
	return ret;
}

static int write_advice(
	struct pqcp_fleet_cbor_writer *writer,
	const struct pqcp_fleet_eat_claims *claims)
{
	int ret = write_label(
		writer, PQCP_FLEET_EAT_CLAIM_ADVICE);

	if (ret == 0) {
		ret = pqcp_fleet_cbor_write_array(
			writer, claims->advice_count);
	}
	for (size_t index = 0U;
	     ret == 0 && index < claims->advice_count;
	     ++index) {
		ret = pqcp_fleet_cbor_write_int(
			writer, claims->advice[index]);
	}
	return ret;
}

static int write_private_value(
	struct pqcp_fleet_cbor_writer *writer,
	const struct pqcp_fleet_eat_private_claim *claim)
{
	switch (claim->type) {
	case PQCP_FLEET_EAT_PRIVATE_UINT:
		return pqcp_fleet_cbor_write_uint(
			writer,
			claim->value.unsigned_value);
	case PQCP_FLEET_EAT_PRIVATE_INT:
		return pqcp_fleet_cbor_write_int(
			writer,
			claim->value.integer_value);
	case PQCP_FLEET_EAT_PRIVATE_BOOL:
		return pqcp_fleet_cbor_write_bool(
			writer,
			claim->value.boolean_value);
	case PQCP_FLEET_EAT_PRIVATE_BYTES:
		return pqcp_fleet_cbor_write_bytes(
			writer, claim->value.bytes.data,
			claim->value.bytes.length);
	case PQCP_FLEET_EAT_PRIVATE_TEXT:
		return pqcp_fleet_cbor_write_text(
			writer, claim->value.text,
			claim->text_length);
	default:
		return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
	}
}

static int write_private_claims(
	struct pqcp_fleet_cbor_writer *writer,
	const struct pqcp_fleet_eat_claims *claims)
{
	bool emitted[PQCP_FLEET_EAT_MAX_PRIVATE_CLAIMS] = { false };
	int ret = 0;

	for (size_t output_index = 0U;
	     output_index < claims->private_claim_count;
	     ++output_index) {
		size_t selected = SIZE_MAX;

		for (size_t index = 0U;
		     index < claims->private_claim_count; ++index) {
			if (emitted[index]) {
				continue;
			}
			if (selected == SIZE_MAX ||
			    private_claim_order(
				    &claims->private_claims[index],
				    &claims->private_claims[selected]) < 0) {
				selected = index;
			}
		}
		if (selected == SIZE_MAX) {
			return PQCP_FLEET_COSE_ERR_ENCODING;
		}
		emitted[selected] = true;
		ret = write_label(
			writer,
			claims->private_claims[selected].label);
		if (ret == 0) {
			ret = write_private_value(
				writer,
				&claims->private_claims[selected]);
		}
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

int pqcp_fleet_eat_claims_encode(
	const struct pqcp_fleet_eat_claims *claims,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_fleet_cbor_writer writer;
	int ret = pqcp_fleet_eat_claims_validate(claims);

	if (ret != 0 || output == NULL ||
	    output_length == NULL) {
		return ret != 0 ? ret :
			PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	pqcp_fleet_cbor_writer_init(
		&writer, output, output_capacity);
	ret = pqcp_fleet_cbor_write_map(
		&writer, claims_field_count(claims));

#define WRITE_IF(condition, expression) \
	do { \
		if (ret == 0 && (condition)) { \
			ret = (expression); \
		} \
	} while (0)

	WRITE_IF(
		text_length(claims->issuer,
			    sizeof(claims->issuer)) != 0U,
		write_text_claim(
			&writer, PQCP_FLEET_CWT_CLAIM_ISSUER,
			claims->issuer, sizeof(claims->issuer)));
	WRITE_IF(
		text_length(claims->subject,
			    sizeof(claims->subject)) != 0U,
		write_text_claim(
			&writer, PQCP_FLEET_CWT_CLAIM_SUBJECT,
			claims->subject, sizeof(claims->subject)));
	WRITE_IF(
		text_length(claims->audience,
			    sizeof(claims->audience)) != 0U,
		write_text_claim(
			&writer, PQCP_FLEET_CWT_CLAIM_AUDIENCE,
			claims->audience, sizeof(claims->audience)));
	WRITE_IF(
		claims->expiration_present,
		write_uint_claim(
			&writer,
			PQCP_FLEET_CWT_CLAIM_EXPIRATION,
			claims->expiration));
	WRITE_IF(
		claims->not_before_present,
		write_uint_claim(
			&writer,
			PQCP_FLEET_CWT_CLAIM_NOT_BEFORE,
			claims->not_before));
	WRITE_IF(
		claims->issued_at_present,
		write_uint_claim(
			&writer,
			PQCP_FLEET_CWT_CLAIM_ISSUED_AT,
			claims->issued_at));
	WRITE_IF(
		claims->token_id_length != 0U,
		write_bytes_claim(
			&writer, PQCP_FLEET_CWT_CLAIM_TOKEN_ID,
			claims->token_id,
			claims->token_id_length));
	WRITE_IF(
		true,
		write_bytes_claim(
			&writer, PQCP_FLEET_EAT_CLAIM_NONCE,
			claims->nonce, claims->nonce_length));
	WRITE_IF(
		true,
		write_bytes_claim(
			&writer, PQCP_FLEET_EAT_CLAIM_UEID,
			claims->ueid, claims->ueid_length));
	WRITE_IF(
		claims->oem_id != 0U,
		write_uint_claim(
			&writer, PQCP_FLEET_EAT_CLAIM_OEM_ID,
			claims->oem_id));
	WRITE_IF(
		claims->hardware_model_length != 0U,
		write_bytes_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_HARDWARE_MODEL,
			claims->hardware_model,
			claims->hardware_model_length));
	WRITE_IF(
		text_length(claims->hardware_version,
			    sizeof(claims->hardware_version)) != 0U,
		write_text_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_HARDWARE_VERSION,
			claims->hardware_version,
			sizeof(claims->hardware_version)));
	WRITE_IF(
		claims->uptime_present,
		write_uint_claim(
			&writer, PQCP_FLEET_EAT_CLAIM_UPTIME,
			claims->uptime_seconds));
	WRITE_IF(
		true,
		write_bool_claim(
			&writer, PQCP_FLEET_EAT_CLAIM_OEM_BOOT,
			claims->oem_boot));
	WRITE_IF(
		claims->debug_status_present,
		write_int_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_DEBUG_STATUS,
			claims->debug_status));
	WRITE_IF(
		true,
		write_text_claim(
			&writer, PQCP_FLEET_EAT_CLAIM_PROFILE,
			claims->profile, sizeof(claims->profile)));
	WRITE_IF(
		claims->boot_count_present,
		write_uint_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_BOOT_COUNT,
			claims->boot_count));
	WRITE_IF(
		text_length(claims->software_name,
			    sizeof(claims->software_name)) != 0U,
		write_text_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_SOFTWARE_NAME,
			claims->software_name,
			sizeof(claims->software_name)));
	WRITE_IF(
		text_length(claims->software_version,
			    sizeof(claims->software_version)) != 0U,
		write_text_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_SOFTWARE_VERSION,
			claims->software_version,
			sizeof(claims->software_version)));
	WRITE_IF(
		claims->measurement_count != 0U,
		write_measurements(&writer, claims));
	WRITE_IF(
		true,
		write_int_claim(
			&writer, PQCP_FLEET_EAT_CLAIM_ROLE,
			claims->role));
	WRITE_IF(
		claims->policy_epoch_present,
		write_uint_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_POLICY_EPOCH,
			claims->policy_epoch));
	WRITE_IF(
		claims->revocation_epoch_present,
		write_uint_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_REVOCATION_EPOCH,
			claims->revocation_epoch));
	WRITE_IF(
		claims->credential_epoch_present,
		write_uint_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_CREDENTIAL_EPOCH,
			claims->credential_epoch));
	WRITE_IF(
		claims->runtime_state_present,
		write_int_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_RUNTIME_STATE,
			claims->runtime_state));
	WRITE_IF(
		claims->risk_score_present,
		write_uint_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_RISK_SCORE,
			claims->risk_score));
	WRITE_IF(
		claims->capabilities_present,
		write_uint_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_CAPABILITIES,
			claims->capabilities));
	WRITE_IF(
		claims->firmware_digest_length != 0U,
		write_bytes_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_FIRMWARE_DIGEST,
			claims->firmware_digest,
			claims->firmware_digest_length));
	WRITE_IF(
		claims->policy_digest_length != 0U,
		write_bytes_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_POLICY_DIGEST,
			claims->policy_digest,
			claims->policy_digest_length));
	WRITE_IF(
		claims->audit_root_length != 0U,
		write_bytes_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_AUDIT_ROOT,
			claims->audit_root,
			claims->audit_root_length));
	WRITE_IF(
		claims->channel_binding_length != 0U,
		write_bytes_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_CHANNEL_BINDING,
			claims->channel_binding,
			claims->channel_binding_length));
	WRITE_IF(
		claims->appraisal_present,
		write_int_claim(
			&writer, PQCP_FLEET_EAT_CLAIM_RESULT,
			claims->appraisal));
	WRITE_IF(
		claims->result_reason_present,
		write_uint_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_RESULT_REASON,
			claims->result_reason));
	WRITE_IF(
		claims->evidence_digest_length != 0U,
		write_bytes_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_EVIDENCE_DIGEST,
			claims->evidence_digest,
			claims->evidence_digest_length));
	WRITE_IF(
		claims->reference_set_present,
		write_uint_claim(
			&writer,
			PQCP_FLEET_EAT_CLAIM_REFERENCE_SET,
			claims->reference_set));
	WRITE_IF(
		claims->advice_count != 0U,
		write_advice(&writer, claims));
	WRITE_IF(
		claims->private_claim_count != 0U,
		write_private_claims(&writer, claims));

#undef WRITE_IF
	if (ret == 0) {
		ret = pqcp_fleet_cbor_writer_finish(
			&writer, output_length);
	}
	return ret;
}

static int copy_text(
	const struct pqcp_fleet_cbor_slice *slice,
	char *output,
	size_t capacity)
{
	if (slice == NULL || output == NULL ||
	    slice->length == 0U ||
	    slice->length >= capacity) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	/* Text claims are consumed as C strings (the profile claim is
	 * compared with strcmp). An embedded NUL would decode to a truncated
	 * string that re-encodes to different bytes than the signed payload.
	 */
	if (memchr(slice->data, '\0', slice->length) != NULL) {
		return PQCP_FLEET_COSE_ERR_ENCODING;
	}
	memcpy(output, slice->data, slice->length);
	output[slice->length] = '\0';
	return 0;
}

static int copy_bytes(
	const struct pqcp_fleet_cbor_slice *slice,
	uint8_t *output,
	size_t capacity,
	size_t *length)
{
	if (slice == NULL || output == NULL || length == NULL ||
	    slice->length > capacity) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	if (slice->length != 0U) {
		memcpy(output, slice->data, slice->length);
	}
	*length = slice->length;
	return 0;
}

static int read_measurement(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_eat_measurement *measurement)
{
	struct pqcp_fleet_cbor_map_cursor cursor;
	struct pqcp_fleet_cbor_map_key key;
	struct pqcp_fleet_cbor_slice slice;
	int64_t value;
	bool system = false;
	bool identifier = false;
	bool result_present = false;
	int ret = pqcp_fleet_cbor_read_map(reader, &cursor);

	if (ret != 0) {
		return ret;
	}
	memset(measurement, 0, sizeof(*measurement));
	while (cursor.remaining != 0U) {
		ret = pqcp_fleet_cbor_map_next(
			reader, &cursor, &key);
		if (ret != 0 || !key.integer) {
			return ret != 0 ? ret :
				PQCP_FLEET_COSE_ERR_ENCODING;
		}
		switch (key.integer_value) {
		case EAT_MEASUREMENT_LABEL_SYSTEM:
			ret = pqcp_fleet_cbor_read_text(
				reader, &slice);
			if (ret == 0) {
				ret = copy_text(
					&slice,
					measurement->system,
					sizeof(measurement->system));
			}
			system = ret == 0;
			break;
		case EAT_MEASUREMENT_LABEL_IDENTIFIER:
			ret = pqcp_fleet_cbor_read_text(
				reader, &slice);
			if (ret == 0) {
				ret = copy_text(
					&slice,
					measurement->identifier,
					sizeof(measurement->identifier));
			}
			identifier = ret == 0;
			break;
		case EAT_MEASUREMENT_LABEL_RESULT:
			ret = pqcp_fleet_cbor_read_int(
				reader, &value);
			if (ret == 0 &&
			    (value <
				     PQCP_FLEET_EAT_MEASUREMENT_SUCCESS ||
			     value >
				     PQCP_FLEET_EAT_MEASUREMENT_ABSENT)) {
				ret =
					PQCP_FLEET_COSE_ERR_ENCODING;
			}
			if (ret == 0) {
				measurement->result =
					(enum pqcp_fleet_eat_measurement_result)
						value;
				result_present = true;
			}
			break;
		case EAT_MEASUREMENT_LABEL_DIGEST:
			ret = pqcp_fleet_cbor_read_bytes(
				reader, &slice);
			if (ret == 0) {
				ret = copy_bytes(
					&slice,
					measurement->digest,
					sizeof(measurement->digest),
					&measurement->digest_length);
			}
			break;
		default:
			return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
		}
		if (ret != 0) {
			return ret;
		}
	}
	return system && identifier && result_present ?
		measurement_validate(measurement) :
		PQCP_FLEET_COSE_ERR_REQUIRED;
}

static int read_measurements(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_eat_claims *claims)
{
	size_t count;
	int ret = pqcp_fleet_cbor_read_array(reader, &count);

	if (ret != 0 || count >
		    PQCP_FLEET_EAT_MAX_MEASUREMENTS) {
		return ret != 0 ? ret :
			PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	for (size_t index = 0U; index < count; ++index) {
		ret = read_measurement(
			reader, &claims->measurements[index]);
		if (ret != 0) {
			return ret;
		}
	}
	claims->measurement_count = count;
	return 0;
}

static int read_advice(
	struct pqcp_fleet_cbor_reader *reader,
	struct pqcp_fleet_eat_claims *claims)
{
	size_t count;
	int64_t value;
	int ret = pqcp_fleet_cbor_read_array(reader, &count);

	if (ret != 0 || count >
		    PQCP_FLEET_EAT_MAX_ADVICE) {
		return ret != 0 ? ret :
			PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	for (size_t index = 0U; index < count; ++index) {
		ret = pqcp_fleet_cbor_read_int(reader, &value);
		if (ret != 0 ||
		    value < PQCP_FLEET_EAT_ADVICE_ALLOW ||
		    value > PQCP_FLEET_EAT_ADVICE_REENROLL) {
			return ret != 0 ? ret :
				PQCP_FLEET_COSE_ERR_ENCODING;
		}
		claims->advice[index] =
			(enum pqcp_fleet_eat_advice)value;
	}
	claims->advice_count = count;
	return 0;
}

static int read_private_claim(
	struct pqcp_fleet_cbor_reader *reader,
	int64_t label,
	struct pqcp_fleet_eat_claims *claims)
{
	struct pqcp_fleet_eat_private_claim *claim;
	struct pqcp_fleet_cbor_reader probe;
	struct pqcp_fleet_cbor_head head;
	struct pqcp_fleet_cbor_slice slice;
	int64_t integer;
	uint64_t unsigned_value;
	bool boolean;
	int ret;

	if (label > EAT_USER_PRIVATE_LABEL_MAX ||
	    claims->private_claim_count >=
		    PQCP_FLEET_EAT_MAX_PRIVATE_CLAIMS) {
		return PQCP_FLEET_COSE_ERR_UNSUPPORTED;
	}
	claim = &claims->private_claims[
		claims->private_claim_count];
	memset(claim, 0, sizeof(*claim));
	claim->label = label;
	probe = *reader;
	ret = pqcp_fleet_cbor_read_head(&probe, &head);
	if (ret != 0) {
		return ret;
	}
	switch (head.major) {
	case PQCP_FLEET_CBOR_UNSIGNED:
		ret = pqcp_fleet_cbor_read_uint(
			reader, &unsigned_value);
		if (ret == 0) {
			claim->type =
				PQCP_FLEET_EAT_PRIVATE_UINT;
			claim->value.unsigned_value =
				unsigned_value;
		}
		break;
	case PQCP_FLEET_CBOR_NEGATIVE:
		ret = pqcp_fleet_cbor_read_int(
			reader, &integer);
		if (ret == 0) {
			claim->type =
				PQCP_FLEET_EAT_PRIVATE_INT;
			claim->value.integer_value = integer;
		}
		break;
	case PQCP_FLEET_CBOR_SIMPLE:
		ret = pqcp_fleet_cbor_read_bool(
			reader, &boolean);
		if (ret == 0) {
			claim->type =
				PQCP_FLEET_EAT_PRIVATE_BOOL;
			claim->value.boolean_value = boolean;
		}
		break;
	case PQCP_FLEET_CBOR_BYTES:
		ret = pqcp_fleet_cbor_read_bytes(
			reader, &slice);
		if (ret == 0) {
			claim->type =
				PQCP_FLEET_EAT_PRIVATE_BYTES;
			claim->value.bytes.data = slice.data;
			claim->value.bytes.length =
				slice.length;
		}
		break;
	case PQCP_FLEET_CBOR_TEXT:
		ret = pqcp_fleet_cbor_read_text(
			reader, &slice);
		if (ret == 0) {
			claim->type =
				PQCP_FLEET_EAT_PRIVATE_TEXT;
			claim->value.text =
				(const char *)slice.data;
			claim->text_length = slice.length;
		}
		break;
	default:
		ret = PQCP_FLEET_COSE_ERR_UNSUPPORTED;
		break;
	}
	if (ret == 0) {
		claims->private_claim_count++;
	}
	return ret;
}

static int read_known_claim(
	struct pqcp_fleet_cbor_reader *reader,
	int64_t label,
	struct pqcp_fleet_eat_claims *claims)
{
	struct pqcp_fleet_cbor_slice slice;
	int64_t integer;
	uint64_t unsigned_value;
	bool boolean;
	int ret;

#define READ_TEXT(target) \
	do { \
		ret = pqcp_fleet_cbor_read_text(reader, &slice); \
		if (ret == 0) { \
			ret = copy_text(&slice, target, sizeof(target)); \
		} \
	} while (0)
#define READ_BYTES(target, length_field) \
	do { \
		ret = pqcp_fleet_cbor_read_bytes(reader, &slice); \
		if (ret == 0) { \
			ret = copy_bytes( \
				&slice, target, sizeof(target), \
				&length_field); \
		} \
	} while (0)
#define READ_UINT(target, present) \
	do { \
		ret = pqcp_fleet_cbor_read_uint( \
			reader, &unsigned_value); \
		if (ret == 0) { \
			target = unsigned_value; \
			present = true; \
		} \
	} while (0)

	ret = 0;
	switch (label) {
	case PQCP_FLEET_CWT_CLAIM_ISSUER:
		READ_TEXT(claims->issuer);
		break;
	case PQCP_FLEET_CWT_CLAIM_SUBJECT:
		READ_TEXT(claims->subject);
		break;
	case PQCP_FLEET_CWT_CLAIM_AUDIENCE:
		READ_TEXT(claims->audience);
		break;
	case PQCP_FLEET_CWT_CLAIM_EXPIRATION:
		READ_UINT(
			claims->expiration,
			claims->expiration_present);
		break;
	case PQCP_FLEET_CWT_CLAIM_NOT_BEFORE:
		READ_UINT(
			claims->not_before,
			claims->not_before_present);
		break;
	case PQCP_FLEET_CWT_CLAIM_ISSUED_AT:
		READ_UINT(
			claims->issued_at,
			claims->issued_at_present);
		break;
	case PQCP_FLEET_CWT_CLAIM_TOKEN_ID:
		READ_BYTES(
			claims->token_id,
			claims->token_id_length);
		break;
	case PQCP_FLEET_EAT_CLAIM_NONCE:
		READ_BYTES(
			claims->nonce, claims->nonce_length);
		break;
	case PQCP_FLEET_EAT_CLAIM_UEID:
		READ_BYTES(
			claims->ueid, claims->ueid_length);
		break;
	case PQCP_FLEET_EAT_CLAIM_OEM_ID:
		ret = pqcp_fleet_cbor_read_uint(
			reader, &unsigned_value);
		if (ret == 0 && unsigned_value > UINT32_MAX) {
			ret = PQCP_FLEET_COSE_ERR_CAPACITY;
		}
		if (ret == 0) {
			claims->oem_id =
				(uint32_t)unsigned_value;
		}
		break;
	case PQCP_FLEET_EAT_CLAIM_HARDWARE_MODEL:
		READ_BYTES(
			claims->hardware_model,
			claims->hardware_model_length);
		break;
	case PQCP_FLEET_EAT_CLAIM_HARDWARE_VERSION:
		READ_TEXT(claims->hardware_version);
		break;
	case PQCP_FLEET_EAT_CLAIM_UPTIME:
		READ_UINT(
			claims->uptime_seconds,
			claims->uptime_present);
		break;
	case PQCP_FLEET_EAT_CLAIM_OEM_BOOT:
		ret = pqcp_fleet_cbor_read_bool(
			reader, &boolean);
		if (ret == 0) {
			claims->oem_boot = boolean;
		}
		break;
	case PQCP_FLEET_EAT_CLAIM_DEBUG_STATUS:
		ret = pqcp_fleet_cbor_read_int(
			reader, &integer);
		if (ret == 0) {
			claims->debug_status =
				(enum pqcp_fleet_eat_debug_status)
					integer;
			claims->debug_status_present = true;
		}
		break;
	case PQCP_FLEET_EAT_CLAIM_PROFILE:
		READ_TEXT(claims->profile);
		break;
	case PQCP_FLEET_EAT_CLAIM_BOOT_COUNT:
		READ_UINT(
			claims->boot_count,
			claims->boot_count_present);
		break;
	case PQCP_FLEET_EAT_CLAIM_SOFTWARE_NAME:
		READ_TEXT(claims->software_name);
		break;
	case PQCP_FLEET_EAT_CLAIM_SOFTWARE_VERSION:
		READ_TEXT(claims->software_version);
		break;
	case PQCP_FLEET_EAT_CLAIM_MEASUREMENTS:
		ret = read_measurements(reader, claims);
		break;
	case PQCP_FLEET_EAT_CLAIM_ROLE:
		ret = pqcp_fleet_cbor_read_int(
			reader, &integer);
		if (ret == 0) {
			claims->role =
				(enum pqcp_fleet_eat_role)integer;
		}
		break;
	case PQCP_FLEET_EAT_CLAIM_POLICY_EPOCH:
		READ_UINT(
			claims->policy_epoch,
			claims->policy_epoch_present);
		break;
	case PQCP_FLEET_EAT_CLAIM_REVOCATION_EPOCH:
		READ_UINT(
			claims->revocation_epoch,
			claims->revocation_epoch_present);
		break;
	case PQCP_FLEET_EAT_CLAIM_CREDENTIAL_EPOCH:
		READ_UINT(
			claims->credential_epoch,
			claims->credential_epoch_present);
		break;
	case PQCP_FLEET_EAT_CLAIM_RUNTIME_STATE:
		ret = pqcp_fleet_cbor_read_int(
			reader, &integer);
		if (ret == 0) {
			claims->runtime_state =
				(enum pqcp_fleet_eat_runtime_state)
					integer;
			claims->runtime_state_present = true;
		}
		break;
	case PQCP_FLEET_EAT_CLAIM_RISK_SCORE:
		ret = pqcp_fleet_cbor_read_uint(
			reader, &unsigned_value);
		if (ret == 0 && unsigned_value > UINT32_MAX) {
			ret = PQCP_FLEET_COSE_ERR_CAPACITY;
		}
		if (ret == 0) {
			claims->risk_score =
				(uint32_t)unsigned_value;
			claims->risk_score_present = true;
		}
		break;
	case PQCP_FLEET_EAT_CLAIM_CAPABILITIES:
		READ_UINT(
			claims->capabilities,
			claims->capabilities_present);
		break;
	case PQCP_FLEET_EAT_CLAIM_FIRMWARE_DIGEST:
		READ_BYTES(
			claims->firmware_digest,
			claims->firmware_digest_length);
		break;
	case PQCP_FLEET_EAT_CLAIM_POLICY_DIGEST:
		READ_BYTES(
			claims->policy_digest,
			claims->policy_digest_length);
		break;
	case PQCP_FLEET_EAT_CLAIM_AUDIT_ROOT:
		READ_BYTES(
			claims->audit_root,
			claims->audit_root_length);
		break;
	case PQCP_FLEET_EAT_CLAIM_CHANNEL_BINDING:
		READ_BYTES(
			claims->channel_binding,
			claims->channel_binding_length);
		break;
	case PQCP_FLEET_EAT_CLAIM_RESULT:
		ret = pqcp_fleet_cbor_read_int(
			reader, &integer);
		if (ret == 0) {
			claims->appraisal =
				(enum pqcp_fleet_eat_appraisal)
					integer;
			claims->appraisal_present = true;
		}
		break;
	case PQCP_FLEET_EAT_CLAIM_RESULT_REASON:
		ret = pqcp_fleet_cbor_read_uint(
			reader, &unsigned_value);
		if (ret == 0 && unsigned_value > UINT32_MAX) {
			ret = PQCP_FLEET_COSE_ERR_CAPACITY;
		}
		if (ret == 0) {
			claims->result_reason =
				(uint32_t)unsigned_value;
			claims->result_reason_present = true;
		}
		break;
	case PQCP_FLEET_EAT_CLAIM_EVIDENCE_DIGEST:
		READ_BYTES(
			claims->evidence_digest,
			claims->evidence_digest_length);
		break;
	case PQCP_FLEET_EAT_CLAIM_REFERENCE_SET:
		READ_UINT(
			claims->reference_set,
			claims->reference_set_present);
		break;
	case PQCP_FLEET_EAT_CLAIM_ADVICE:
		ret = read_advice(reader, claims);
		break;
	default:
		ret = read_private_claim(
			reader, label, claims);
		break;
	}

#undef READ_TEXT
#undef READ_BYTES
#undef READ_UINT
	return ret;
}

int pqcp_fleet_eat_claims_decode(
	const uint8_t *encoded,
	size_t encoded_length,
	struct pqcp_fleet_eat_claims *claims)
{
	struct pqcp_fleet_cbor_reader reader;
	struct pqcp_fleet_cbor_map_cursor cursor;
	struct pqcp_fleet_cbor_map_key key;
	int ret;

	if (encoded == NULL || encoded_length == 0U ||
	    claims == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	memset(claims, 0, sizeof(*claims));
	pqcp_fleet_cbor_reader_init(
		&reader, encoded, encoded_length);
	ret = pqcp_fleet_cbor_read_map(&reader, &cursor);
	if (ret != 0) {
		return ret;
	}
	while (cursor.remaining != 0U) {
		ret = pqcp_fleet_cbor_map_next(
			&reader, &cursor, &key);
		if (ret != 0 || !key.integer) {
			ret = ret != 0 ? ret :
				PQCP_FLEET_COSE_ERR_ENCODING;
			break;
		}
		ret = read_known_claim(
			&reader, key.integer_value, claims);
		if (ret != 0) {
			break;
		}
	}
	if (ret == 0) {
		ret = pqcp_fleet_cbor_reader_finish(&reader);
	}
	if (ret == 0) {
		ret = pqcp_fleet_eat_claims_validate(claims);
	}
	if (ret != 0) {
		memset(claims, 0, sizeof(*claims));
	}
	return ret;
}

static void default_eat_headers(
	const struct pqcp_fleet_eat_claims *claims,
	const uint8_t *key_id,
	size_t key_id_length,
	struct pqcp_fleet_cose_headers *headers)
{
	const char *content_type =
		claims->role ==
			PQCP_FLEET_EAT_ROLE_ATTESTATION_RESULT ?
			PQCP_FLEET_EAT_RESULT_CONTENT_TYPE :
			PQCP_FLEET_EAT_CONTENT_TYPE;
	const size_t content_length = strlen(content_type);

	memset(headers, 0, sizeof(*headers));
	headers->algorithm =
		PQCP_FLEET_COSE_ALG_ML_DSA_65;
	headers->content_type_kind =
		PQCP_FLEET_COSE_CONTENT_TYPE_TEXT;
	memcpy(headers->content_type_text,
	       content_type, content_length + 1U);
	if (key_id_length != 0U) {
		memcpy(headers->kid, key_id, key_id_length);
		headers->kid_length = key_id_length;
	}
	headers->critical[0] = PQCP_FLEET_COSE_HEADER_ALG;
	headers->critical[1] =
		PQCP_FLEET_COSE_HEADER_CONTENT_TYPE;
	headers->critical_count = 2U;
	headers->tagged = true;
}

int pqcp_fleet_eat_token_sign(
	const struct pqcp_fleet_eat_claims *claims,
	const uint8_t *key_id,
	size_t key_id_length,
	const struct pqcp_fleet_cose_crypto *crypto,
	uint8_t *workspace,
	size_t workspace_capacity,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_fleet_cose_headers headers;
	size_t claims_length = 0U;
	int ret;

	if ((key_id == NULL && key_id_length != 0U) ||
	    key_id_length > PQCP_FLEET_COSE_MAX_KID_BYTES ||
	    crypto == NULL || workspace == NULL ||
	    output == NULL || output_length == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_eat_claims_encode(
		claims, workspace, workspace_capacity,
		&claims_length);
	if (ret != 0) {
		return ret;
	}
	if (claims_length >= workspace_capacity) {
		return PQCP_FLEET_COSE_ERR_CAPACITY;
	}
	default_eat_headers(
		claims, key_id, key_id_length, &headers);
	ret = pqcp_fleet_cose_sign1_sign(
		&headers, NULL, workspace, claims_length,
		NULL, 0U, crypto,
		workspace + claims_length,
		workspace_capacity - claims_length,
		output, output_capacity, output_length);
	memset(workspace, 0, workspace_capacity);
	return ret;
}

int pqcp_fleet_eat_token_verify(
	const uint8_t *token,
	size_t token_length,
	const struct pqcp_fleet_cose_crypto *crypto,
	const struct pqcp_fleet_eat_freshness *freshness,
	uint8_t *workspace,
	size_t workspace_capacity,
	struct pqcp_fleet_eat_claims *claims)
{
	struct pqcp_fleet_cose_sign1 sign1;
	int ret;

	if (token == NULL || token_length == 0U ||
	    crypto == NULL || workspace == NULL ||
	    claims == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_cose_sign1_verify(
		token, token_length, NULL, 0U, NULL, 0U,
		crypto, workspace, workspace_capacity, &sign1);
	if (ret != 0) {
		return ret;
	}
	if (sign1.detached_payload ||
	    sign1.protected_headers.algorithm !=
		    PQCP_FLEET_COSE_ALG_ML_DSA_65 ||
	    sign1.protected_headers.content_type_kind !=
		    PQCP_FLEET_COSE_CONTENT_TYPE_TEXT) {
		return PQCP_FLEET_COSE_ERR_POLICY;
	}
	ret = pqcp_fleet_eat_claims_decode(
		sign1.payload.data, sign1.payload.length, claims);
	if (ret == 0 && freshness != NULL) {
		ret = pqcp_fleet_eat_freshness_check(
			claims, freshness);
	}
	return ret;
}

int pqcp_fleet_eat_claims_digest(
	const struct pqcp_fleet_eat_claims *claims,
	const struct pqcp_fleet_cose_crypto *crypto,
	uint8_t output[PQCP_FLEET_EAT_DIGEST_BYTES])
{
	uint8_t encoded[8192];
	size_t encoded_length = 0U;
	size_t digest_length = 0U;
	int ret;

	if (crypto == NULL || crypto->hash == NULL ||
	    output == NULL) {
		return PQCP_FLEET_COSE_ERR_ARGUMENT;
	}
	ret = pqcp_fleet_eat_claims_encode(
		claims, encoded, sizeof(encoded),
		&encoded_length);
	if (ret == 0) {
		ret = crypto->hash(
			crypto->context, encoded, encoded_length,
			output, PQCP_FLEET_EAT_DIGEST_BYTES,
			&digest_length);
		if (ret != 0) {
			ret = PQCP_FLEET_COSE_ERR_CRYPTO;
		}
	}
	memset(encoded, 0, sizeof(encoded));
	if (ret == 0 &&
	    digest_length != PQCP_FLEET_EAT_DIGEST_BYTES) {
		memset(output, 0, PQCP_FLEET_EAT_DIGEST_BYTES);
		ret = PQCP_FLEET_COSE_ERR_CRYPTO;
	}
	return ret;
}
