/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Canonical sovereign event construction, validation, and projection.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include "runtime_internal.h"
#include "sovereign_audit_internal.h"

#define EVENT_NUMERIC_BYTES 112U
#define ATTRIBUTE_NUMERIC_BYTES 16U
#define EVENT_HASH_PARTS 24U
#define EVENT_ID_PARTS 12U
#define SCOPE_HASH_PARTS 7U

static const char hexadecimal[] = "0123456789abcdef";

static bool event_class_valid(
	enum pqcp_sovereign_audit_event_class event_class)
{
	return event_class > PQCP_SOVEREIGN_AUDIT_CLASS_NONE &&
	       event_class < PQCP_SOVEREIGN_AUDIT_CLASS_COUNT;
}

static bool activity_valid(
	enum pqcp_sovereign_audit_activity activity)
{
	return activity > PQCP_SOVEREIGN_AUDIT_ACTIVITY_NONE &&
	       activity < PQCP_SOVEREIGN_AUDIT_ACTIVITY_COUNT;
}

static bool severity_valid(
	enum pqcp_sovereign_audit_severity severity)
{
	return severity >=
		       PQCP_SOVEREIGN_AUDIT_SEVERITY_UNKNOWN &&
	       severity <=
		       PQCP_SOVEREIGN_AUDIT_SEVERITY_CRITICAL;
}

static bool outcome_valid(
	enum pqcp_sovereign_audit_outcome outcome)
{
	return outcome >= PQCP_SOVEREIGN_AUDIT_OUTCOME_UNKNOWN &&
	       outcome <= PQCP_SOVEREIGN_AUDIT_OUTCOME_EXPIRED;
}

static bool data_class_valid(
	enum pqcp_sovereign_audit_data_class data_class)
{
	return data_class >= PQCP_SOVEREIGN_AUDIT_DATA_PUBLIC &&
	       data_class < PQCP_SOVEREIGN_AUDIT_DATA_CLASS_COUNT;
}

static bool redaction_valid(
	enum pqcp_sovereign_audit_redaction redaction)
{
	return redaction >= PQCP_SOVEREIGN_AUDIT_REDACTION_NONE &&
	       redaction <= PQCP_SOVEREIGN_AUDIT_REDACTION_STRICT;
}

static uint32_t known_event_flags(void)
{
	return PQCP_SOVEREIGN_AUDIT_EVENT_SECURITY_RELEVANT |
	       PQCP_SOVEREIGN_AUDIT_EVENT_OPERATOR_VISIBLE |
	       PQCP_SOVEREIGN_AUDIT_EVENT_REGULATORY |
	       PQCP_SOVEREIGN_AUDIT_EVENT_PRIVACY_RELEVANT |
	       PQCP_SOVEREIGN_AUDIT_EVENT_RECOVERY_RELEVANT |
	       PQCP_SOVEREIGN_AUDIT_EVENT_REDACTED |
	       PQCP_SOVEREIGN_AUDIT_EVENT_CHECKPOINT |
	       PQCP_SOVEREIGN_AUDIT_EVENT_SIGNED_SOURCE;
}

static uint32_t known_attribute_flags(void)
{
	return PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_PERSONAL |
	       PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_SENSITIVE |
	       PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_REGULATORY;
}

static bool attribute_type_valid(
	enum pqcp_sovereign_audit_attribute_type type)
{
	return type >= PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_U64 &&
	       type <= PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_DIGEST;
}

static bool key_character_valid(char value)
{
	return (value >= 'a' && value <= 'z') ||
	       (value >= 'A' && value <= 'Z') ||
	       (value >= '0' && value <= '9') ||
	       value == '_' || value == '-' || value == '.';
}

static bool attribute_key_valid(const char *key)
{
	size_t length;

	if (key == NULL) {
		return false;
	}
	length = strnlen(
		key, PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_KEY_MAX_CHARS);
	if (length == 0U ||
	    length >= PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_KEY_MAX_CHARS) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		if (!key_character_valid(key[index])) {
			return false;
		}
	}
	return true;
}

static bool attribute_valid(
	const struct pqcp_sovereign_audit_attribute *attribute)
{
	if (attribute == NULL ||
	    !attribute_key_valid(attribute->key) ||
	    !attribute_type_valid(attribute->type) ||
	    (attribute->flags & ~known_attribute_flags()) != 0U) {
		return false;
	}
	if (attribute->type ==
		    PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT &&
	    !pqcp_sovereign_audit_internal_text_valid(
		    attribute->value.text,
		    sizeof(attribute->value.text), true)) {
		return false;
	}
	return true;
}

bool pqcp_sovereign_audit_internal_all_zero(
	const uint8_t *bytes,
	size_t length)
{
	uint8_t aggregate = 0U;

	if (bytes == NULL) {
		return true;
	}
	for (size_t index = 0U; index < length; ++index) {
		aggregate |= bytes[index];
	}
	return aggregate == 0U;
}

bool pqcp_sovereign_audit_internal_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	if (left == NULL || right == NULL) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

bool pqcp_sovereign_audit_internal_text_valid(
	const char *text,
	size_t capacity,
	bool allow_empty)
{
	size_t length;

	if (text == NULL || capacity == 0U) {
		return false;
	}
	length = strnlen(text, capacity);
	if (length >= capacity || (!allow_empty && length == 0U)) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		unsigned char value = (unsigned char)text[index];

		if (value < 0x20U || value > 0x7eU) {
			return false;
		}
	}
	return true;
}

int pqcp_sovereign_audit_internal_copy_text(
	char *destination,
	size_t capacity,
	const char *source,
	bool allow_empty)
{
	size_t length;

	if (destination == NULL || capacity == 0U ||
	    !pqcp_sovereign_audit_internal_text_valid(
		    source, capacity, allow_empty)) {
		return -EINVAL;
	}
	length = strnlen(source, capacity);
	memset(destination, 0, capacity);
	if (length != 0U) {
		memcpy(destination, source, length);
	}
	return 0;
}

uint64_t pqcp_sovereign_audit_internal_add_u64(
	uint64_t left,
	uint64_t right)
{
	if (UINT64_MAX - left < right) {
		return UINT64_MAX;
	}
	return left + right;
}

uint32_t pqcp_sovereign_audit_internal_next_generation(
	uint32_t *generation)
{
	uint32_t value;

	if (generation == NULL) {
		return 0U;
	}
	value = *generation;
	if (value == 0U) {
		value = 1U;
	}
	*generation = value == UINT32_MAX ? 1U : value + 1U;
	return value;
}

uint64_t pqcp_sovereign_audit_internal_next_id(
	uint64_t *identifier)
{
	uint64_t value;

	if (identifier == NULL) {
		return 0U;
	}
	value = *identifier;
	if (value == 0U) {
		value = 1U;
	}
	*identifier = value == UINT64_MAX ? 1U : value + 1U;
	return value;
}

void pqcp_sovereign_audit_internal_write_u16(
	uint8_t output[2],
	uint16_t value)
{
	output[0] = (uint8_t)(value >> 8U);
	output[1] = (uint8_t)value;
}

void pqcp_sovereign_audit_internal_write_u32(
	uint8_t output[4],
	uint32_t value)
{
	output[0] = (uint8_t)(value >> 24U);
	output[1] = (uint8_t)(value >> 16U);
	output[2] = (uint8_t)(value >> 8U);
	output[3] = (uint8_t)value;
}

void pqcp_sovereign_audit_internal_write_u64(
	uint8_t output[8],
	uint64_t value)
{
	for (size_t index = 0U; index < 8U; ++index) {
		output[index] =
			(uint8_t)(value >> (56U - index * 8U));
	}
}

int pqcp_sovereign_audit_internal_sha256(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES])
{
	return pqcp_runtime_internal_sha256(
		input, input_length, output);
}

int pqcp_sovereign_audit_internal_sha256_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES])
{
	return pqcp_runtime_internal_sha256_parts(
		parts, lengths, part_count, output);
}

int pqcp_sovereign_audit_internal_scope_digest(
	const struct pqcp_sovereign_audit_tenant_scope *scope,
	uint8_t digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES])
{
	uint8_t numeric[16U];
	const uint8_t *parts[SCOPE_HASH_PARTS];
	size_t lengths[SCOPE_HASH_PARTS];

	if (scope == NULL || digest == NULL ||
	    !pqcp_sovereign_audit_internal_text_valid(
		    scope->tenant_id, sizeof(scope->tenant_id), false) ||
	    !pqcp_sovereign_audit_internal_text_valid(
		    scope->realm, sizeof(scope->realm), true)) {
		return -EINVAL;
	}
	pqcp_sovereign_audit_internal_write_u64(
		numeric, scope->policy_epoch);
	pqcp_sovereign_audit_internal_write_u64(
		numeric + 8U, scope->revocation_epoch);
	parts[0] = (const uint8_t *)
		PQCP_SOVEREIGN_AUDIT_TENANT_DOMAIN;
	lengths[0] = sizeof(PQCP_SOVEREIGN_AUDIT_TENANT_DOMAIN) -
		     1U;
	parts[1] = (const uint8_t *)scope->tenant_id;
	lengths[1] = strnlen(
		scope->tenant_id, sizeof(scope->tenant_id));
	parts[2] = (const uint8_t *)"\0";
	lengths[2] = 1U;
	parts[3] = (const uint8_t *)scope->realm;
	lengths[3] = strnlen(scope->realm, sizeof(scope->realm));
	parts[4] = (const uint8_t *)"\0";
	lengths[4] = 1U;
	parts[5] = numeric;
	lengths[5] = sizeof(numeric);
	parts[6] = (const uint8_t *)"\1";
	lengths[6] = 1U;
	return pqcp_sovereign_audit_internal_sha256_parts(
		parts, lengths, SCOPE_HASH_PARTS, digest);
}

int pqcp_sovereign_audit_internal_projection_digest(
	const char *tenant_id,
	const char *value,
	size_t value_capacity,
	uint8_t digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES])
{
	const uint8_t *parts[5U];
	size_t lengths[5U];
	size_t value_length;

	if (!pqcp_sovereign_audit_internal_text_valid(
		    tenant_id, PQCP_SOVEREIGN_AUDIT_TENANT_MAX_CHARS,
		    false) ||
	    !pqcp_sovereign_audit_internal_text_valid(
		    value, value_capacity, true) ||
	    digest == NULL) {
		return -EINVAL;
	}
	value_length = strnlen(value, value_capacity);
	parts[0] = (const uint8_t *)
		PQCP_SOVEREIGN_AUDIT_PSEUDONYM_DOMAIN;
	lengths[0] =
		sizeof(PQCP_SOVEREIGN_AUDIT_PSEUDONYM_DOMAIN) - 1U;
	parts[1] = (const uint8_t *)tenant_id;
	lengths[1] = strnlen(
		tenant_id, PQCP_SOVEREIGN_AUDIT_TENANT_MAX_CHARS);
	parts[2] = (const uint8_t *)"\0";
	lengths[2] = 1U;
	parts[3] = (const uint8_t *)value;
	lengths[3] = value_length;
	parts[4] = (const uint8_t *)"\0";
	lengths[4] = 1U;
	return pqcp_sovereign_audit_internal_sha256_parts(
		parts, lengths, 5U, digest);
}

const char *pqcp_sovereign_audit_event_class_str(
	enum pqcp_sovereign_audit_event_class event_class)
{
	switch (event_class) {
	case PQCP_SOVEREIGN_AUDIT_CLASS_CRYPTO_OPERATION:
		return "crypto_operation";
	case PQCP_SOVEREIGN_AUDIT_CLASS_FLEET_OPERATION:
		return "fleet_operation";
	case PQCP_SOVEREIGN_AUDIT_CLASS_SECURITY_INCIDENT:
		return "security_incident";
	case PQCP_SOVEREIGN_AUDIT_CLASS_DEPLOYMENT:
		return "deployment";
	case PQCP_SOVEREIGN_AUDIT_CLASS_KEY_CEREMONY:
		return "key_ceremony";
	case PQCP_SOVEREIGN_AUDIT_CLASS_PRIVACY:
		return "privacy";
	case PQCP_SOVEREIGN_AUDIT_CLASS_RECOVERY:
		return "recovery";
	case PQCP_SOVEREIGN_AUDIT_CLASS_CONTINUITY:
		return "continuity";
	case PQCP_SOVEREIGN_AUDIT_CLASS_AUDIT_CONTROL:
		return "audit_control";
	default:
		return "none";
	}
}

const char *pqcp_sovereign_audit_activity_str(
	enum pqcp_sovereign_audit_activity activity)
{
	switch (activity) {
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_CREATE:
		return "create";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_START:
		return "start";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_UPDATE:
		return "update";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_AUTHORIZE:
		return "authorize";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_APPROVE:
		return "approve";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_REJECT:
		return "reject";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_EXECUTE:
		return "execute";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_COMPLETE:
		return "complete";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_CANCEL:
		return "cancel";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_EXPIRE:
		return "expire";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_REVOKE:
		return "revoke";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_ROTATE:
		return "rotate";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_DESTROY:
		return "destroy";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_DEPLOY:
		return "deploy";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_ROLLBACK:
		return "rollback";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_QUARANTINE:
		return "quarantine";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_CONTAIN:
		return "contain";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_REMEDIATE:
		return "remediate";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_RECOVER:
		return "recover";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_FAILOVER:
		return "failover";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_REJOIN:
		return "rejoin";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_READ:
		return "read";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_WRITE:
		return "write";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_EXPORT:
		return "export";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_ERASE:
		return "erase";
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_ACKNOWLEDGE:
		return "acknowledge";
	default:
		return "none";
	}
}

const char *pqcp_sovereign_audit_severity_str(
	enum pqcp_sovereign_audit_severity severity)
{
	switch (severity) {
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_INFORMATIONAL:
		return "informational";
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_LOW:
		return "low";
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_MEDIUM:
		return "medium";
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_HIGH:
		return "high";
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_CRITICAL:
		return "critical";
	default:
		return "unknown";
	}
}

const char *pqcp_sovereign_audit_outcome_str(
	enum pqcp_sovereign_audit_outcome outcome)
{
	switch (outcome) {
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_SUCCESS:
		return "success";
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_FAILURE:
		return "failure";
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_DENIED:
		return "denied";
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_PENDING:
		return "pending";
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_CANCELLED:
		return "cancelled";
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_EXPIRED:
		return "expired";
	default:
		return "unknown";
	}
}

static int copy_optional_digest(
	uint8_t destination[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES],
	const uint8_t *source)
{
	memset(destination, 0,
	       PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES);
	if (source != NULL) {
		memcpy(destination, source,
		       PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES);
	}
	return 0;
}

int pqcp_sovereign_event_init(
	struct pqcp_sovereign_event *event,
	const struct pqcp_sovereign_event_draft *draft)
{
	int ret;

	if (event == NULL || draft == NULL ||
	    !event_class_valid(draft->event_class) ||
	    !activity_valid(draft->activity) ||
	    !severity_valid(draft->severity) ||
	    !outcome_valid(draft->outcome) ||
	    !data_class_valid(draft->data_class) ||
	    draft->observed_at_ms == 0U ||
	    draft->ingested_at_ms < draft->observed_at_ms ||
	    (draft->expires_at_ms != 0U &&
	     draft->expires_at_ms <= draft->observed_at_ms) ||
	    (draft->flags & ~known_event_flags()) != 0U) {
		return -EINVAL;
	}
	memset(event, 0, sizeof(*event));
	event->schema_version =
		PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION;
	event->generation = 1U;
	event->observed_at_ms = draft->observed_at_ms;
	event->ingested_at_ms = draft->ingested_at_ms;
	event->expires_at_ms = draft->expires_at_ms;
	event->correlation_id = draft->correlation_id;
	event->policy_epoch = draft->policy_epoch;
	event->revocation_epoch = draft->revocation_epoch;
	event->event_class = draft->event_class;
	event->activity = draft->activity;
	event->severity = draft->severity;
	event->outcome = draft->outcome;
	event->data_class = draft->data_class;
	event->flags = draft->flags;
	event->result = draft->result;
	event->tenant.policy_epoch = draft->policy_epoch;
	event->tenant.revocation_epoch = draft->revocation_epoch;
	ret = pqcp_sovereign_audit_internal_copy_text(
		event->tenant.tenant_id,
		sizeof(event->tenant.tenant_id),
		draft->tenant_id, false);
	if (ret == 0) {
		ret = pqcp_sovereign_audit_internal_copy_text(
			event->tenant.realm,
			sizeof(event->tenant.realm),
			draft->realm != NULL ? draft->realm : "",
			true);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_audit_internal_copy_text(
			event->source, sizeof(event->source),
			draft->source, false);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_audit_internal_copy_text(
			event->actor, sizeof(event->actor),
			draft->actor != NULL ? draft->actor : "",
			true);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_audit_internal_copy_text(
			event->object, sizeof(event->object),
			draft->object != NULL ? draft->object : "",
			true);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_audit_internal_copy_text(
			event->action, sizeof(event->action),
			draft->action != NULL ? draft->action : "",
			true);
	}
	if (ret == 0) {
		ret = pqcp_sovereign_audit_internal_copy_text(
			event->reason, sizeof(event->reason),
			draft->reason != NULL ? draft->reason : "",
			true);
	}
	if (ret != 0) {
		memset(event, 0, sizeof(*event));
		return ret;
	}
	copy_optional_digest(
		event->actor_digest, draft->actor_digest);
	copy_optional_digest(
		event->subject_digest, draft->subject_digest);
	copy_optional_digest(
		event->resource_digest, draft->resource_digest);
	copy_optional_digest(
		event->evidence_digest, draft->evidence_digest);
	copy_optional_digest(
		event->receipt_digest, draft->receipt_digest);
	ret = pqcp_sovereign_audit_internal_scope_digest(
		&event->tenant, event->tenant.scope_digest);
	if (ret == 0) {
		ret = pqcp_sovereign_event_derive_id(event);
	}
	if (ret != 0) {
		memset(event, 0, sizeof(*event));
	}
	return ret;
}

int pqcp_sovereign_event_set_id(
	struct pqcp_sovereign_event *event,
	const uint8_t event_id[PQCP_SOVEREIGN_AUDIT_EVENT_ID_BYTES])
{
	if (event == NULL || event_id == NULL ||
	    pqcp_sovereign_audit_internal_all_zero(
		    event_id, PQCP_SOVEREIGN_AUDIT_EVENT_ID_BYTES)) {
		return -EINVAL;
	}
	memcpy(event->event_id, event_id,
	       sizeof(event->event_id));
	return 0;
}

int pqcp_sovereign_event_derive_id(
	struct pqcp_sovereign_event *event)
{
	uint8_t numeric[48U];
	uint8_t digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	const uint8_t *parts[EVENT_ID_PARTS];
	size_t lengths[EVENT_ID_PARTS];
	int ret;

	if (event == NULL ||
	    event->schema_version !=
		    PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION ||
	    !event_class_valid(event->event_class) ||
	    !activity_valid(event->activity) ||
	    event->observed_at_ms == 0U) {
		return -EINVAL;
	}
	memset(numeric, 0, sizeof(numeric));
	pqcp_sovereign_audit_internal_write_u32(
		numeric, event->schema_version);
	pqcp_sovereign_audit_internal_write_u32(
		numeric + 4U, event->generation);
	pqcp_sovereign_audit_internal_write_u32(
		numeric + 8U, (uint32_t)event->event_class);
	pqcp_sovereign_audit_internal_write_u32(
		numeric + 12U, (uint32_t)event->activity);
	pqcp_sovereign_audit_internal_write_u64(
		numeric + 16U, event->observed_at_ms);
	pqcp_sovereign_audit_internal_write_u64(
		numeric + 24U, event->correlation_id);
	pqcp_sovereign_audit_internal_write_u64(
		numeric + 32U, event->policy_epoch);
	pqcp_sovereign_audit_internal_write_u64(
		numeric + 40U, event->revocation_epoch);
	parts[0] = (const uint8_t *)
		PQCP_SOVEREIGN_AUDIT_EVENT_ID_DOMAIN;
	lengths[0] =
		sizeof(PQCP_SOVEREIGN_AUDIT_EVENT_ID_DOMAIN) - 1U;
	parts[1] = numeric;
	lengths[1] = sizeof(numeric);
	parts[2] = (const uint8_t *)event->tenant.tenant_id;
	lengths[2] = strnlen(
		event->tenant.tenant_id,
		sizeof(event->tenant.tenant_id));
	parts[3] = (const uint8_t *)event->source;
	lengths[3] = strnlen(event->source, sizeof(event->source));
	parts[4] = (const uint8_t *)event->actor;
	lengths[4] = strnlen(event->actor, sizeof(event->actor));
	parts[5] = (const uint8_t *)event->object;
	lengths[5] = strnlen(event->object, sizeof(event->object));
	parts[6] = event->actor_digest;
	lengths[6] = sizeof(event->actor_digest);
	parts[7] = event->subject_digest;
	lengths[7] = sizeof(event->subject_digest);
	parts[8] = event->resource_digest;
	lengths[8] = sizeof(event->resource_digest);
	parts[9] = event->evidence_digest;
	lengths[9] = sizeof(event->evidence_digest);
	parts[10] = event->receipt_digest;
	lengths[10] = sizeof(event->receipt_digest);
	parts[11] = (const uint8_t *)event->action;
	lengths[11] = strnlen(
		event->action, sizeof(event->action));
	ret = pqcp_sovereign_audit_internal_sha256_parts(
		parts, lengths, EVENT_ID_PARTS, digest);
	if (ret == 0) {
		memcpy(event->event_id, digest,
		       sizeof(event->event_id));
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
	pqcp_runtime_secure_zero(numeric, sizeof(numeric));
	return ret;
}

static int attribute_position(
	const struct pqcp_sovereign_event *event,
	const char *key,
	size_t *position,
	bool *duplicate)
{
	if (event == NULL || !attribute_key_valid(key) ||
	    position == NULL || duplicate == NULL ||
	    event->attribute_count >
		    PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES) {
		return -EINVAL;
	}
	*duplicate = false;
	*position = event->attribute_count;
	for (size_t index = 0U;
	     index < event->attribute_count; ++index) {
		int comparison = strcmp(
			key, event->attributes[index].key);

		if (comparison == 0) {
			*position = index;
			*duplicate = true;
			return 0;
		}
		if (comparison < 0) {
			*position = index;
			return 0;
		}
	}
	return 0;
}

static int insert_attribute(
	struct pqcp_sovereign_event *event,
	const struct pqcp_sovereign_audit_attribute *attribute)
{
	size_t position;
	bool duplicate;
	int ret;

	if (event == NULL || !attribute_valid(attribute) ||
	    event->attribute_count >=
		    PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES) {
		return -EINVAL;
	}
	ret = attribute_position(
		event, attribute->key, &position, &duplicate);
	if (ret != 0) {
		return ret;
	}
	if (duplicate) {
		return -EEXIST;
	}
	if (position < event->attribute_count) {
		memmove(
			&event->attributes[position + 1U],
			&event->attributes[position],
			(event->attribute_count - position) *
				sizeof(event->attributes[0]));
	}
	event->attributes[position] = *attribute;
	event->attribute_count++;
	return 0;
}

static int initialize_attribute(
	struct pqcp_sovereign_audit_attribute *attribute,
	const char *key,
	enum pqcp_sovereign_audit_attribute_type type,
	uint32_t flags)
{
	int ret;

	if (attribute == NULL || !attribute_key_valid(key) ||
	    !attribute_type_valid(type) ||
	    (flags & ~known_attribute_flags()) != 0U) {
		return -EINVAL;
	}
	memset(attribute, 0, sizeof(*attribute));
	ret = pqcp_sovereign_audit_internal_copy_text(
		attribute->key, sizeof(attribute->key),
		key, false);
	if (ret == 0) {
		attribute->type = type;
		attribute->flags = flags;
	}
	return ret;
}

int pqcp_sovereign_event_add_u64(
	struct pqcp_sovereign_event *event,
	const char *key,
	uint64_t value,
	uint32_t flags)
{
	struct pqcp_sovereign_audit_attribute attribute;
	int ret = initialize_attribute(
		&attribute, key,
		PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_U64, flags);

	if (ret == 0) {
		attribute.value.u64 = value;
		ret = insert_attribute(event, &attribute);
	}
	return ret;
}

int pqcp_sovereign_event_add_i64(
	struct pqcp_sovereign_event *event,
	const char *key,
	int64_t value,
	uint32_t flags)
{
	struct pqcp_sovereign_audit_attribute attribute;
	int ret = initialize_attribute(
		&attribute, key,
		PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_I64, flags);

	if (ret == 0) {
		attribute.value.i64 = value;
		ret = insert_attribute(event, &attribute);
	}
	return ret;
}

int pqcp_sovereign_event_add_bool(
	struct pqcp_sovereign_event *event,
	const char *key,
	bool value,
	uint32_t flags)
{
	struct pqcp_sovereign_audit_attribute attribute;
	int ret = initialize_attribute(
		&attribute, key,
		PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_BOOL, flags);

	if (ret == 0) {
		attribute.value.boolean = value;
		ret = insert_attribute(event, &attribute);
	}
	return ret;
}

int pqcp_sovereign_event_add_text(
	struct pqcp_sovereign_event *event,
	const char *key,
	const char *value,
	uint32_t flags)
{
	struct pqcp_sovereign_audit_attribute attribute;
	int ret = initialize_attribute(
		&attribute, key,
		PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT, flags);

	if (ret == 0) {
		ret = pqcp_sovereign_audit_internal_copy_text(
			attribute.value.text,
			sizeof(attribute.value.text),
			value, true);
	}
	if (ret == 0) {
		ret = insert_attribute(event, &attribute);
	}
	return ret;
}

int pqcp_sovereign_event_add_digest(
	struct pqcp_sovereign_event *event,
	const char *key,
	const uint8_t value[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES],
	uint32_t flags)
{
	struct pqcp_sovereign_audit_attribute attribute;
	int ret;

	if (value == NULL) {
		return -EINVAL;
	}
	ret = initialize_attribute(
		&attribute, key,
		PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_DIGEST, flags);
	if (ret == 0) {
		memcpy(attribute.value.digest, value,
		       sizeof(attribute.value.digest));
		ret = insert_attribute(event, &attribute);
	}
	return ret;
}

static int attributes_digest(
	const struct pqcp_sovereign_event *event,
	uint8_t digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES])
{
	uint8_t aggregate[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES] = { 0 };
	uint8_t next[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t numeric[ATTRIBUTE_NUMERIC_BYTES];
	const uint8_t *parts[5U];
	size_t lengths[5U];
	int ret = 0;

	if (event == NULL || digest == NULL ||
	    event->attribute_count >
		    PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES) {
		return -EINVAL;
	}
	for (size_t index = 0U;
	     index < event->attribute_count; ++index) {
		const struct pqcp_sovereign_audit_attribute *attribute =
			&event->attributes[index];
		const uint8_t *value;
		size_t value_length;

		if (!attribute_valid(attribute)) {
			ret = -EINVAL;
			break;
		}
		memset(numeric, 0, sizeof(numeric));
		pqcp_sovereign_audit_internal_write_u32(
			numeric, (uint32_t)attribute->type);
		pqcp_sovereign_audit_internal_write_u32(
			numeric + 4U, attribute->flags);
		switch (attribute->type) {
		case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_U64:
			pqcp_sovereign_audit_internal_write_u64(
				numeric + 8U, attribute->value.u64);
			value = numeric + 8U;
			value_length = 8U;
			break;
		case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_I64:
			pqcp_sovereign_audit_internal_write_u64(
				numeric + 8U,
				(uint64_t)attribute->value.i64);
			value = numeric + 8U;
			value_length = 8U;
			break;
		case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_BOOL:
			numeric[8U] =
				attribute->value.boolean ? 1U : 0U;
			value = numeric + 8U;
			value_length = 1U;
			break;
		case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT:
			value = (const uint8_t *)
				attribute->value.text;
			value_length = strnlen(
				attribute->value.text,
				sizeof(attribute->value.text));
			break;
		case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_DIGEST:
			value = attribute->value.digest;
			value_length =
				sizeof(attribute->value.digest);
			break;
		default:
			ret = -EINVAL;
			value = NULL;
			value_length = 0U;
			break;
		}
		if (ret != 0) {
			break;
		}
		parts[0] = aggregate;
		lengths[0] = sizeof(aggregate);
		parts[1] = (const uint8_t *)attribute->key;
		lengths[1] = strnlen(
			attribute->key, sizeof(attribute->key));
		parts[2] = numeric;
		lengths[2] = 8U;
		parts[3] = value;
		lengths[3] = value_length;
		parts[4] = (const uint8_t *)"\0";
		lengths[4] = 1U;
		ret = pqcp_sovereign_audit_internal_sha256_parts(
			parts, lengths, 5U, next);
		if (ret != 0) {
			break;
		}
		memcpy(aggregate, next, sizeof(aggregate));
	}
	if (ret == 0) {
		memcpy(digest, aggregate,
		       PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES);
	}
	pqcp_runtime_secure_zero(aggregate, sizeof(aggregate));
	pqcp_runtime_secure_zero(next, sizeof(next));
	pqcp_runtime_secure_zero(numeric, sizeof(numeric));
	return ret;
}

int pqcp_sovereign_event_digest(
	const struct pqcp_sovereign_event *event,
	uint8_t digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES])
{
	uint8_t numeric[EVENT_NUMERIC_BYTES];
	uint8_t attribute_digest[
		PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	const uint8_t *parts[EVENT_HASH_PARTS];
	size_t lengths[EVENT_HASH_PARTS];
	size_t offset = 0U;
	int ret;

	if (event == NULL || digest == NULL ||
	    event->schema_version !=
		    PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION ||
	    event->generation == 0U || event->sequence == 0U ||
	    event->observed_at_ms == 0U ||
	    event->ingested_at_ms < event->observed_at_ms ||
	    !event_class_valid(event->event_class) ||
	    !activity_valid(event->activity) ||
	    !severity_valid(event->severity) ||
	    !outcome_valid(event->outcome) ||
	    !data_class_valid(event->data_class) ||
	    (event->flags & ~known_event_flags()) != 0U ||
	    event->attribute_count >
		    PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES ||
	    pqcp_sovereign_audit_internal_all_zero(
		    event->event_id, sizeof(event->event_id))) {
		return -EINVAL;
	}
	ret = attributes_digest(event, attribute_digest);
	if (ret != 0) {
		return ret;
	}
	memset(numeric, 0, sizeof(numeric));
	pqcp_sovereign_audit_internal_write_u32(
		numeric + offset, event->schema_version);
	offset += 4U;
	pqcp_sovereign_audit_internal_write_u32(
		numeric + offset, event->generation);
	offset += 4U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, event->sequence);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, event->observed_at_ms);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, event->ingested_at_ms);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, event->expires_at_ms);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, event->correlation_id);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, event->policy_epoch);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u64(
		numeric + offset, event->revocation_epoch);
	offset += 8U;
	pqcp_sovereign_audit_internal_write_u32(
		numeric + offset, (uint32_t)event->event_class);
	offset += 4U;
	pqcp_sovereign_audit_internal_write_u32(
		numeric + offset, (uint32_t)event->activity);
	offset += 4U;
	pqcp_sovereign_audit_internal_write_u32(
		numeric + offset, (uint32_t)event->severity);
	offset += 4U;
	pqcp_sovereign_audit_internal_write_u32(
		numeric + offset, (uint32_t)event->outcome);
	offset += 4U;
	pqcp_sovereign_audit_internal_write_u32(
		numeric + offset, (uint32_t)event->data_class);
	offset += 4U;
	pqcp_sovereign_audit_internal_write_u32(
		numeric + offset, event->flags);
	offset += 4U;
	pqcp_sovereign_audit_internal_write_u32(
		numeric + offset, (uint32_t)event->result);
	offset += 4U;
	pqcp_sovereign_audit_internal_write_u32(
		numeric + offset, event->attribute_count);
	offset += 4U;
	parts[0] = (const uint8_t *)
		PQCP_SOVEREIGN_AUDIT_EVENT_HASH_DOMAIN;
	lengths[0] =
		sizeof(PQCP_SOVEREIGN_AUDIT_EVENT_HASH_DOMAIN) - 1U;
	parts[1] = numeric;
	lengths[1] = offset;
	parts[2] = event->event_id;
	lengths[2] = sizeof(event->event_id);
	parts[3] = event->tenant.scope_digest;
	lengths[3] = sizeof(event->tenant.scope_digest);
	parts[4] = (const uint8_t *)event->source;
	lengths[4] = sizeof(event->source);
	parts[5] = (const uint8_t *)event->actor;
	lengths[5] = sizeof(event->actor);
	parts[6] = (const uint8_t *)event->object;
	lengths[6] = sizeof(event->object);
	parts[7] = (const uint8_t *)event->action;
	lengths[7] = sizeof(event->action);
	parts[8] = (const uint8_t *)event->reason;
	lengths[8] = sizeof(event->reason);
	parts[9] = event->actor_digest;
	lengths[9] = sizeof(event->actor_digest);
	parts[10] = event->subject_digest;
	lengths[10] = sizeof(event->subject_digest);
	parts[11] = event->resource_digest;
	lengths[11] = sizeof(event->resource_digest);
	parts[12] = event->evidence_digest;
	lengths[12] = sizeof(event->evidence_digest);
	parts[13] = event->receipt_digest;
	lengths[13] = sizeof(event->receipt_digest);
	parts[14] = event->previous_digest;
	lengths[14] = sizeof(event->previous_digest);
	parts[15] = attribute_digest;
	lengths[15] = sizeof(attribute_digest);
	parts[16] = (const uint8_t *)event->tenant.tenant_id;
	lengths[16] = sizeof(event->tenant.tenant_id);
	parts[17] = (const uint8_t *)event->tenant.realm;
	lengths[17] = sizeof(event->tenant.realm);
	parts[18] = (const uint8_t *)"\0";
	lengths[18] = 1U;
	parts[19] = event->tenant.scope_digest;
	lengths[19] = sizeof(event->tenant.scope_digest);
	parts[20] = event->resource_digest;
	lengths[20] = sizeof(event->resource_digest);
	parts[21] = event->evidence_digest;
	lengths[21] = sizeof(event->evidence_digest);
	parts[22] = event->receipt_digest;
	lengths[22] = sizeof(event->receipt_digest);
	parts[23] = attribute_digest;
	lengths[23] = sizeof(attribute_digest);
	ret = pqcp_sovereign_audit_internal_sha256_parts(
		parts, lengths, EVENT_HASH_PARTS, digest);
	pqcp_runtime_secure_zero(numeric, sizeof(numeric));
	pqcp_runtime_secure_zero(
		attribute_digest, sizeof(attribute_digest));
	return ret;
}

static int text_fields_verify(
	const struct pqcp_sovereign_event *event)
{
	if (!pqcp_sovereign_audit_internal_text_valid(
		    event->tenant.tenant_id,
		    sizeof(event->tenant.tenant_id), false) ||
	    !pqcp_sovereign_audit_internal_text_valid(
		    event->tenant.realm,
		    sizeof(event->tenant.realm), true) ||
	    !pqcp_sovereign_audit_internal_text_valid(
		    event->source, sizeof(event->source), false) ||
	    !pqcp_sovereign_audit_internal_text_valid(
		    event->actor, sizeof(event->actor), true) ||
	    !pqcp_sovereign_audit_internal_text_valid(
		    event->object, sizeof(event->object), true) ||
	    !pqcp_sovereign_audit_internal_text_valid(
		    event->action, sizeof(event->action), true) ||
	    !pqcp_sovereign_audit_internal_text_valid(
		    event->reason, sizeof(event->reason), true)) {
		return -EINVAL;
	}
	return 0;
}

int pqcp_sovereign_event_verify(
	const struct pqcp_sovereign_event *event)
{
	uint8_t scope_digest[
		PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	uint8_t event_digest[
		PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];
	int ret;

	if (event == NULL || !event->occupied ||
	    event->schema_version !=
		    PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION ||
	    event->generation == 0U || event->sequence == 0U ||
	    event->observed_at_ms == 0U ||
	    event->ingested_at_ms < event->observed_at_ms ||
	    (event->expires_at_ms != 0U &&
	     event->expires_at_ms <= event->observed_at_ms) ||
	    event->tenant.policy_epoch != event->policy_epoch ||
	    event->tenant.revocation_epoch !=
		    event->revocation_epoch ||
	    !event_class_valid(event->event_class) ||
	    !activity_valid(event->activity) ||
	    !severity_valid(event->severity) ||
	    !outcome_valid(event->outcome) ||
	    !data_class_valid(event->data_class) ||
	    (event->flags & ~known_event_flags()) != 0U ||
	    event->attribute_count >
		    PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES ||
	    pqcp_sovereign_audit_internal_all_zero(
		    event->event_id, sizeof(event->event_id)) ||
	    pqcp_sovereign_audit_internal_all_zero(
		    event->event_digest,
		    sizeof(event->event_digest))) {
		return -EINVAL;
	}
	ret = text_fields_verify(event);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < event->attribute_count; ++index) {
		if (!attribute_valid(&event->attributes[index])) {
			return -EINVAL;
		}
		if (index != 0U &&
		    strcmp(event->attributes[index - 1U].key,
			   event->attributes[index].key) >= 0) {
			return -EBADMSG;
		}
	}
	ret = pqcp_sovereign_audit_internal_scope_digest(
		&event->tenant, scope_digest);
	if (ret == 0 &&
	    !pqcp_sovereign_audit_internal_equal(
		    scope_digest, event->tenant.scope_digest,
		    sizeof(scope_digest))) {
		ret = -EBADMSG;
	}
	if (ret == 0) {
		ret = pqcp_sovereign_event_digest(
			event, event_digest);
	}
	if (ret == 0 &&
	    !pqcp_sovereign_audit_internal_equal(
		    event_digest, event->event_digest,
		    sizeof(event_digest))) {
		ret = -EBADMSG;
	}
	pqcp_runtime_secure_zero(
		scope_digest, sizeof(scope_digest));
	pqcp_runtime_secure_zero(
		event_digest, sizeof(event_digest));
	return ret;
}

static void pseudonym_text(
	const char *tenant_id,
	const char *source,
	size_t source_capacity,
	char *destination,
	size_t destination_capacity)
{
	uint8_t digest[PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];

	memset(destination, 0, destination_capacity);
	if (source == NULL || source[0] == '\0' ||
	    destination_capacity < 19U ||
	    pqcp_sovereign_audit_internal_projection_digest(
		    tenant_id, source, source_capacity,
		    digest) != 0) {
		return;
	}
	destination[0] = 'h';
	destination[1] = ':';
	for (size_t index = 0U; index < 8U; ++index) {
		destination[2U + index * 2U] =
			hexadecimal[digest[index] >> 4U];
		destination[3U + index * 2U] =
			hexadecimal[digest[index] & 0x0fU];
	}
	pqcp_runtime_secure_zero(digest, sizeof(digest));
}

static void remove_attribute(
	struct pqcp_sovereign_event *event,
	size_t index)
{
	if (event == NULL ||
	    index >= event->attribute_count) {
		return;
	}
	if (index + 1U < event->attribute_count) {
		memmove(
			&event->attributes[index],
			&event->attributes[index + 1U],
			(event->attribute_count - index - 1U) *
				sizeof(event->attributes[0]));
	}
	event->attribute_count--;
	memset(
		&event->attributes[event->attribute_count], 0,
		sizeof(event->attributes[0]));
}

static void pseudonymize_attributes(
	struct pqcp_sovereign_event *event)
{
	for (size_t index = 0U;
	     index < event->attribute_count; ++index) {
		struct pqcp_sovereign_audit_attribute *attribute =
			&event->attributes[index];
		uint8_t digest[
			PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES];

		if ((attribute->flags &
		     PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_PERSONAL) == 0U) {
			continue;
		}
		if (attribute->type ==
		    PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT) {
			if (pqcp_sovereign_audit_internal_projection_digest(
				    event->tenant.tenant_id,
				    attribute->value.text,
				    sizeof(attribute->value.text),
				    digest) == 0) {
				memset(
					&attribute->value, 0,
					sizeof(attribute->value));
				memcpy(
					attribute->value.digest,
					digest, sizeof(digest));
				attribute->type =
					PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_DIGEST;
			}
			pqcp_runtime_secure_zero(
				digest, sizeof(digest));
		}
	}
}

static void minimize_attributes(
	struct pqcp_sovereign_event *event,
	bool strict)
{
	size_t index = 0U;

	while (index < event->attribute_count) {
		uint32_t flags = event->attributes[index].flags;
		bool remove = strict ||
			(flags &
			 (PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_PERSONAL |
			  PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_SENSITIVE)) !=
				0U;

		if (remove) {
			remove_attribute(event, index);
		} else {
			index++;
		}
	}
}

int pqcp_sovereign_event_redact(
	const struct pqcp_sovereign_event *source,
	enum pqcp_sovereign_audit_redaction mode,
	bool include_attributes,
	bool include_reasons,
	struct pqcp_sovereign_event *projected)
{
	if (source == NULL || projected == NULL ||
	    !redaction_valid(mode) ||
	    source->schema_version !=
		    PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION ||
	    !source->occupied) {
		return -EINVAL;
	}
	*projected = *source;
	if (!include_reasons) {
		memset(projected->reason, 0,
		       sizeof(projected->reason));
	}
	if (!include_attributes) {
		memset(projected->attributes, 0,
		       sizeof(projected->attributes));
		projected->attribute_count = 0U;
	}
	switch (mode) {
	case PQCP_SOVEREIGN_AUDIT_REDACTION_NONE:
		break;
	case PQCP_SOVEREIGN_AUDIT_REDACTION_PSEUDONYMIZE: {
		char actor[sizeof(projected->actor)];
		char object[sizeof(projected->object)];

		pseudonym_text(
			source->tenant.tenant_id,
			source->actor, sizeof(source->actor),
			actor, sizeof(actor));
		pseudonym_text(
			source->tenant.tenant_id,
			source->object, sizeof(source->object),
			object, sizeof(object));
		memcpy(projected->actor, actor, sizeof(actor));
		memcpy(projected->object, object, sizeof(object));
		pseudonymize_attributes(projected);
		projected->flags |=
			PQCP_SOVEREIGN_AUDIT_EVENT_REDACTED;
		pqcp_runtime_secure_zero(actor, sizeof(actor));
		pqcp_runtime_secure_zero(object, sizeof(object));
		break;
	}
	case PQCP_SOVEREIGN_AUDIT_REDACTION_MINIMIZE:
		memset(projected->actor, 0,
		       sizeof(projected->actor));
		memset(projected->reason, 0,
		       sizeof(projected->reason));
		minimize_attributes(projected, false);
		projected->flags |=
			PQCP_SOVEREIGN_AUDIT_EVENT_REDACTED;
		break;
	case PQCP_SOVEREIGN_AUDIT_REDACTION_STRICT:
		memset(projected->actor, 0,
		       sizeof(projected->actor));
		memset(projected->object, 0,
		       sizeof(projected->object));
		memset(projected->reason, 0,
		       sizeof(projected->reason));
		memset(projected->actor_digest, 0,
		       sizeof(projected->actor_digest));
		memset(projected->subject_digest, 0,
		       sizeof(projected->subject_digest));
		minimize_attributes(projected, true);
		(void)pqcp_sovereign_audit_internal_copy_text(
			projected->source,
			sizeof(projected->source),
			"redacted", false);
		projected->flags |=
			PQCP_SOVEREIGN_AUDIT_EVENT_REDACTED;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}
