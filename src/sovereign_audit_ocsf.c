/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * OCSF-aligned JSON projection for sovereign audit evidence.
 */

#include <errno.h>
#include <string.h>

#include "sovereign_audit_internal.h"

static uint32_t ocsf_category_uid(
	enum pqcp_sovereign_audit_event_class event_class)
{
	switch (event_class) {
	case PQCP_SOVEREIGN_AUDIT_CLASS_CRYPTO_OPERATION:
		return 6U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_FLEET_OPERATION:
	case PQCP_SOVEREIGN_AUDIT_CLASS_DEPLOYMENT:
		return 5U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_SECURITY_INCIDENT:
		return 2U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_KEY_CEREMONY:
	case PQCP_SOVEREIGN_AUDIT_CLASS_AUDIT_CONTROL:
		return 6U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_PRIVACY:
		return 3U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_RECOVERY:
	case PQCP_SOVEREIGN_AUDIT_CLASS_CONTINUITY:
		return 5U;
	default:
		return 0U;
	}
}

static uint32_t ocsf_class_uid(
	enum pqcp_sovereign_audit_event_class event_class)
{
	switch (event_class) {
	case PQCP_SOVEREIGN_AUDIT_CLASS_CRYPTO_OPERATION:
		return 6003U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_FLEET_OPERATION:
		return 5001U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_SECURITY_INCIDENT:
		return 2004U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_DEPLOYMENT:
		return 5007U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_KEY_CEREMONY:
		return 6003U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_PRIVACY:
		return 3002U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_RECOVERY:
		return 5008U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_CONTINUITY:
		return 5009U;
	case PQCP_SOVEREIGN_AUDIT_CLASS_AUDIT_CONTROL:
		return 6002U;
	default:
		return 0U;
	}
}

static uint32_t ocsf_activity_id(
	enum pqcp_sovereign_audit_activity activity)
{
	switch (activity) {
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_CREATE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_START:
		return 1U;
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_UPDATE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_REMEDIATE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_ROTATE:
		return 2U;
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_AUTHORIZE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_APPROVE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_EXECUTE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_DEPLOY:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_READ:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_WRITE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_EXPORT:
		return 3U;
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_COMPLETE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_ACKNOWLEDGE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_REJOIN:
		return 4U;
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_CANCEL:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_EXPIRE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_REVOKE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_DESTROY:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_ERASE:
		return 5U;
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_REJECT:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_QUARANTINE:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_CONTAIN:
		return 6U;
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_ROLLBACK:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_RECOVER:
	case PQCP_SOVEREIGN_AUDIT_ACTIVITY_FAILOVER:
		return 7U;
	default:
		return 0U;
	}
}

static uint32_t ocsf_status_id(
	enum pqcp_sovereign_audit_outcome outcome)
{
	switch (outcome) {
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_SUCCESS:
		return 1U;
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_FAILURE:
		return 2U;
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_DENIED:
		return 2U;
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_PENDING:
		return 3U;
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_CANCELLED:
		return 4U;
	case PQCP_SOVEREIGN_AUDIT_OUTCOME_EXPIRED:
		return 5U;
	default:
		return 0U;
	}
}

static uint32_t ocsf_severity_id(
	enum pqcp_sovereign_audit_severity severity)
{
	return (uint32_t)severity;
}

static uint64_t ocsf_type_uid(
	const struct pqcp_sovereign_event *event)
{
	return (uint64_t)ocsf_class_uid(event->event_class) *
		       100U +
	       ocsf_activity_id(event->activity);
}

static void json_key(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const char *key)
{
	if (!*first) {
		pqcp_sovereign_audit_writer_char(writer, ',');
	}
	*first = false;
	pqcp_sovereign_audit_writer_json_text(writer, key);
	pqcp_sovereign_audit_writer_char(writer, ':');
}

static void json_text_field(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const char *key,
	const char *value)
{
	json_key(writer, first, key);
	pqcp_sovereign_audit_writer_json_text(
		writer, value != NULL ? value : "");
}

static void json_u64_field(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const char *key,
	uint64_t value)
{
	json_key(writer, first, key);
	pqcp_sovereign_audit_writer_u64(writer, value);
}

static void json_i64_field(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const char *key,
	int64_t value)
{
	json_key(writer, first, key);
	pqcp_sovereign_audit_writer_i64(writer, value);
}

static void json_bool_field(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const char *key,
	bool value)
{
	json_key(writer, first, key);
	pqcp_sovereign_audit_writer_text(
		writer, value ? "true" : "false");
}

static void json_hex_field(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const char *key,
	const uint8_t *bytes,
	size_t length)
{
	json_key(writer, first, key);
	pqcp_sovereign_audit_writer_char(writer, '"');
	pqcp_sovereign_audit_writer_hex(
		writer, bytes, length);
	pqcp_sovereign_audit_writer_char(writer, '"');
}

static void json_metadata(
	struct pqcp_sovereign_audit_writer *writer,
	const struct pqcp_sovereign_event *event)
{
	bool first = true;

	pqcp_sovereign_audit_writer_char(writer, '{');
	json_text_field(
		writer, &first, "version", "1.4.0");
	json_text_field(
		writer, &first, "log_name",
		"pqcp_sovereign_audit");
	json_text_field(
		writer, &first, "log_provider",
		PQCP_SOVEREIGN_AUDIT_CEF_VENDOR);
	json_text_field(
		writer, &first, "product_name",
		PQCP_SOVEREIGN_AUDIT_CEF_PRODUCT);
	json_text_field(
		writer, &first, "product_version",
		PQCP_SOVEREIGN_AUDIT_CEF_VERSION);
	json_u64_field(
		writer, &first, "logged_time",
		event->ingested_at_ms);
	json_hex_field(
		writer, &first, "uid",
		event->event_id, sizeof(event->event_id));
	pqcp_sovereign_audit_writer_char(writer, '}');
}

static void json_actor(
	struct pqcp_sovereign_audit_writer *writer,
	const struct pqcp_sovereign_event *event)
{
	bool first = true;

	pqcp_sovereign_audit_writer_char(writer, '{');
	json_text_field(
		writer, &first, "user_name", event->actor);
	json_hex_field(
		writer, &first, "user_uid",
		event->actor_digest,
		sizeof(event->actor_digest));
	json_text_field(
		writer, &first, "tenant_uid",
		event->tenant.tenant_id);
	json_text_field(
		writer, &first, "domain",
		event->tenant.realm);
	pqcp_sovereign_audit_writer_char(writer, '}');
}

static void json_device(
	struct pqcp_sovereign_audit_writer *writer,
	const struct pqcp_sovereign_event *event)
{
	bool first = true;

	pqcp_sovereign_audit_writer_char(writer, '{');
	json_text_field(
		writer, &first, "name", event->source);
	json_text_field(
		writer, &first, "type", "embedded");
	json_hex_field(
		writer, &first, "uid",
		event->tenant.scope_digest,
		sizeof(event->tenant.scope_digest));
	pqcp_sovereign_audit_writer_char(writer, '}');
}

static void json_attribute_value(
	struct pqcp_sovereign_audit_writer *writer,
	const struct pqcp_sovereign_audit_attribute *attribute)
{
	switch (attribute->type) {
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_U64:
		pqcp_sovereign_audit_writer_u64(
			writer, attribute->value.u64);
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_I64:
		pqcp_sovereign_audit_writer_i64(
			writer, attribute->value.i64);
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_BOOL:
		pqcp_sovereign_audit_writer_text(
			writer,
			attribute->value.boolean ?
				"true" : "false");
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT:
		pqcp_sovereign_audit_writer_json_text(
			writer, attribute->value.text);
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_DIGEST:
		pqcp_sovereign_audit_writer_char(writer, '"');
		pqcp_sovereign_audit_writer_hex(
			writer, attribute->value.digest,
			sizeof(attribute->value.digest));
		pqcp_sovereign_audit_writer_char(writer, '"');
		break;
	default:
		pqcp_sovereign_audit_writer_text(
			writer, "null");
		break;
	}
}

static void json_unmapped(
	struct pqcp_sovereign_audit_writer *writer,
	const struct pqcp_sovereign_event *event)
{
	bool first = true;

	pqcp_sovereign_audit_writer_char(writer, '{');
	json_u64_field(
		writer, &first, "schema_version",
		event->schema_version);
	json_u64_field(
		writer, &first, "generation",
		event->generation);
	json_u64_field(
		writer, &first, "sequence",
		event->sequence);
	json_u64_field(
		writer, &first, "expires_at",
		event->expires_at_ms);
	json_u64_field(
		writer, &first, "correlation_id",
		event->correlation_id);
	json_u64_field(
		writer, &first, "policy_epoch",
		event->policy_epoch);
	json_u64_field(
		writer, &first, "revocation_epoch",
		event->revocation_epoch);
	json_u64_field(
		writer, &first, "data_class",
		event->data_class);
	json_u64_field(
		writer, &first, "flags",
		event->flags);
	json_i64_field(
		writer, &first, "result",
		event->result);
	json_text_field(
		writer, &first, "object", event->object);
	json_text_field(
		writer, &first, "action", event->action);
	json_hex_field(
		writer, &first, "subject_digest",
		event->subject_digest,
		sizeof(event->subject_digest));
	json_hex_field(
		writer, &first, "resource_digest",
		event->resource_digest,
		sizeof(event->resource_digest));
	json_hex_field(
		writer, &first, "evidence_digest",
		event->evidence_digest,
		sizeof(event->evidence_digest));
	json_hex_field(
		writer, &first, "receipt_digest",
		event->receipt_digest,
		sizeof(event->receipt_digest));
	json_hex_field(
		writer, &first, "previous_digest",
		event->previous_digest,
		sizeof(event->previous_digest));
	json_hex_field(
		writer, &first, "event_digest",
		event->event_digest,
		sizeof(event->event_digest));
	json_key(writer, &first, "attributes");
	pqcp_sovereign_audit_writer_char(writer, '{');
	for (size_t index = 0U;
	     index < event->attribute_count; ++index) {
		const struct pqcp_sovereign_audit_attribute *attribute =
			&event->attributes[index];

		if (index != 0U) {
			pqcp_sovereign_audit_writer_char(
				writer, ',');
		}
		pqcp_sovereign_audit_writer_json_text(
			writer, attribute->key);
		pqcp_sovereign_audit_writer_char(writer, ':');
		json_attribute_value(writer, attribute);
	}
	pqcp_sovereign_audit_writer_char(writer, '}');
	pqcp_sovereign_audit_writer_char(writer, '}');
}

static void write_event(
	struct pqcp_sovereign_audit_writer *writer,
	const struct pqcp_sovereign_event *event)
{
	bool first = true;

	pqcp_sovereign_audit_writer_char(writer, '{');
	json_u64_field(
		writer, &first, "activity_id",
		ocsf_activity_id(event->activity));
	json_text_field(
		writer, &first, "activity_name",
		pqcp_sovereign_audit_activity_str(
			event->activity));
	json_key(writer, &first, "actor");
	json_actor(writer, event);
	json_u64_field(
		writer, &first, "category_uid",
		ocsf_category_uid(event->event_class));
	json_u64_field(
		writer, &first, "class_uid",
		ocsf_class_uid(event->event_class));
	json_text_field(
		writer, &first, "class_name",
		pqcp_sovereign_audit_event_class_str(
			event->event_class));
	json_key(writer, &first, "device");
	json_device(writer, event);
	json_text_field(
		writer, &first, "message", event->reason);
	json_key(writer, &first, "metadata");
	json_metadata(writer, event);
	json_u64_field(
		writer, &first, "severity_id",
		ocsf_severity_id(event->severity));
	json_text_field(
		writer, &first, "severity",
		pqcp_sovereign_audit_severity_str(
			event->severity));
	json_u64_field(
		writer, &first, "status_id",
		ocsf_status_id(event->outcome));
	json_text_field(
		writer, &first, "status",
		pqcp_sovereign_audit_outcome_str(
			event->outcome));
	json_u64_field(
		writer, &first, "time",
		event->observed_at_ms);
	json_u64_field(
		writer, &first, "type_uid",
		ocsf_type_uid(event));
	json_key(writer, &first, "unmapped");
	json_unmapped(writer, event);
	pqcp_sovereign_audit_writer_char(writer, '}');
}

int pqcp_sovereign_audit_ocsf_encode_event(
	const struct pqcp_sovereign_event *event,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_sovereign_audit_writer writer;

	if (event == NULL || output == NULL ||
	    output_capacity == 0U || output_length == NULL ||
	    event->schema_version !=
		    PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION ||
	    !event->occupied ||
	    event->attribute_count >
		    PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES) {
		return -EINVAL;
	}
	*output_length = 0U;
	pqcp_sovereign_audit_writer_init(
		&writer, output, output_capacity);
	write_event(&writer, event);
	return pqcp_sovereign_audit_writer_finish(
		&writer, output_length);
}

static void write_batch_metadata(
	struct pqcp_sovereign_audit_writer *writer,
	const struct pqcp_sovereign_export_batch *batch)
{
	bool first = true;

	pqcp_sovereign_audit_writer_char(writer, '{');
	json_u64_field(
		writer, &first, "schema_version",
		batch->schema_version);
	json_u64_field(
		writer, &first, "cursor_id",
		batch->cursor_id);
	json_u64_field(
		writer, &first, "created_at",
		batch->created_at_ms);
	json_u64_field(
		writer, &first, "policy_epoch",
		batch->policy_epoch);
	json_u64_field(
		writer, &first, "first_sequence",
		batch->first_sequence);
	json_u64_field(
		writer, &first, "last_sequence",
		batch->last_sequence);
	json_u64_field(
		writer, &first, "scanned_through_sequence",
		batch->scanned_through_sequence);
	json_u64_field(
		writer, &first, "event_count",
		batch->event_count);
	json_text_field(
		writer, &first, "tenant_uid",
		batch->tenant_id);
	json_u64_field(
		writer, &first, "redaction_id",
		batch->redaction);
	json_hex_field(
		writer, &first, "source_anchor_digest",
		batch->source_anchor_digest,
		sizeof(batch->source_anchor_digest));
	json_hex_field(
		writer, &first, "source_chain_head",
		batch->source_chain_head,
		sizeof(batch->source_chain_head));
	json_hex_field(
		writer, &first, "previous_batch_digest",
		batch->previous_batch_digest,
		sizeof(batch->previous_batch_digest));
	json_hex_field(
		writer, &first, "receipt_digest",
		batch->receipt_digest,
		sizeof(batch->receipt_digest));
	json_hex_field(
		writer, &first, "batch_digest",
		batch->batch_digest,
		sizeof(batch->batch_digest));
	json_u64_field(
		writer, &first, "signature_algorithm_id",
		batch->signature_algorithm);
	if (batch->signature_length != 0U) {
		json_hex_field(
			writer, &first, "signature",
			batch->signature,
			batch->signature_length);
	}
	json_bool_field(
		writer, &first, "complete", batch->complete);
	json_bool_field(
		writer, &first, "resumed", batch->resumed);
	pqcp_sovereign_audit_writer_char(writer, '}');
}

int pqcp_sovereign_audit_ocsf_encode_batch(
	const struct pqcp_sovereign_export_batch *batch,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_sovereign_audit_writer writer;
	bool first = true;

	if (batch == NULL || output == NULL ||
	    output_capacity == 0U || output_length == NULL ||
	    batch->schema_version !=
		    PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION ||
	    batch->event_count == 0U || batch->events == NULL ||
	    batch->signature_length >
		    sizeof(batch->signature)) {
		return -EINVAL;
	}
	*output_length = 0U;
	pqcp_sovereign_audit_writer_init(
		&writer, output, output_capacity);
	pqcp_sovereign_audit_writer_char(&writer, '{');
	json_key(&writer, &first, "batch");
	write_batch_metadata(&writer, batch);
	json_key(&writer, &first, "events");
	pqcp_sovereign_audit_writer_char(&writer, '[');
	for (size_t index = 0U;
	     index < batch->event_count; ++index) {
		if (index != 0U) {
			pqcp_sovereign_audit_writer_char(
				&writer, ',');
		}
		write_event(&writer, &batch->events[index]);
	}
	pqcp_sovereign_audit_writer_char(&writer, ']');
	pqcp_sovereign_audit_writer_char(&writer, '}');
	return pqcp_sovereign_audit_writer_finish(
		&writer, output_length);
}
