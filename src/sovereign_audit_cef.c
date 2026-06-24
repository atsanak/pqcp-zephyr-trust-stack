/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Escaped CEF records transported as RFC 5424-compatible syslog messages.
 */

#include <errno.h>
#include <string.h>

#include "sovereign_audit_internal.h"

static uint32_t cef_severity(
	enum pqcp_sovereign_audit_severity severity)
{
	switch (severity) {
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_INFORMATIONAL:
		return 2U;
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_LOW:
		return 4U;
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_MEDIUM:
		return 6U;
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_HIGH:
		return 8U;
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_CRITICAL:
		return 10U;
	default:
		return 0U;
	}
}

static uint32_t syslog_priority(
	enum pqcp_sovereign_audit_severity severity)
{
	uint32_t syslog_severity;

	switch (severity) {
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_CRITICAL:
		syslog_severity = 2U;
		break;
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_HIGH:
		syslog_severity = 3U;
		break;
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_MEDIUM:
		syslog_severity = 4U;
		break;
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_LOW:
		syslog_severity = 5U;
		break;
	case PQCP_SOVEREIGN_AUDIT_SEVERITY_INFORMATIONAL:
		syslog_severity = 6U;
		break;
	default:
		syslog_severity = 7U;
		break;
	}
	return 16U * 8U + syslog_severity;
}

static void write_extension_separator(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first)
{
	if (!*first) {
		pqcp_sovereign_audit_writer_char(writer, ' ');
	}
	*first = false;
}

static void write_extension_text(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const char *key,
	const char *value)
{
	write_extension_separator(writer, first);
	pqcp_sovereign_audit_writer_text(writer, key);
	pqcp_sovereign_audit_writer_char(writer, '=');
	pqcp_sovereign_audit_writer_cef_extension_text(
		writer, value != NULL ? value : "");
}

static void write_extension_u64(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const char *key,
	uint64_t value)
{
	write_extension_separator(writer, first);
	pqcp_sovereign_audit_writer_text(writer, key);
	pqcp_sovereign_audit_writer_char(writer, '=');
	pqcp_sovereign_audit_writer_u64(writer, value);
}

static void write_extension_i64(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const char *key,
	int64_t value)
{
	write_extension_separator(writer, first);
	pqcp_sovereign_audit_writer_text(writer, key);
	pqcp_sovereign_audit_writer_char(writer, '=');
	pqcp_sovereign_audit_writer_i64(writer, value);
}

static void write_extension_bool(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const char *key,
	bool value)
{
	write_extension_text(
		writer, first, key, value ? "true" : "false");
}

static void write_extension_hex(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const char *key,
	const uint8_t *bytes,
	size_t length)
{
	write_extension_separator(writer, first);
	pqcp_sovereign_audit_writer_text(writer, key);
	pqcp_sovereign_audit_writer_char(writer, '=');
	pqcp_sovereign_audit_writer_hex(
		writer, bytes, length);
}

static void write_syslog_prefix(
	struct pqcp_sovereign_audit_writer *writer,
	enum pqcp_sovereign_audit_severity severity,
	const char *message_id)
{
	pqcp_sovereign_audit_writer_char(writer, '<');
	pqcp_sovereign_audit_writer_u64(
		writer, syslog_priority(severity));
	pqcp_sovereign_audit_writer_text(
		writer, ">1 - - ");
	pqcp_sovereign_audit_writer_text(
		writer, PQCP_SOVEREIGN_AUDIT_SYSLOG_APP);
	pqcp_sovereign_audit_writer_text(writer, " - ");
	pqcp_sovereign_audit_writer_cef_header_text(
		writer, message_id);
	pqcp_sovereign_audit_writer_text(writer, " - ");
}

static void write_cef_header(
	struct pqcp_sovereign_audit_writer *writer,
	const char *signature,
	const char *name,
	uint32_t severity)
{
	pqcp_sovereign_audit_writer_text(writer, "CEF:0|");
	pqcp_sovereign_audit_writer_cef_header_text(
		writer, PQCP_SOVEREIGN_AUDIT_CEF_VENDOR);
	pqcp_sovereign_audit_writer_char(writer, '|');
	pqcp_sovereign_audit_writer_cef_header_text(
		writer, PQCP_SOVEREIGN_AUDIT_CEF_PRODUCT);
	pqcp_sovereign_audit_writer_char(writer, '|');
	pqcp_sovereign_audit_writer_cef_header_text(
		writer, PQCP_SOVEREIGN_AUDIT_CEF_VERSION);
	pqcp_sovereign_audit_writer_char(writer, '|');
	pqcp_sovereign_audit_writer_cef_header_text(
		writer, signature);
	pqcp_sovereign_audit_writer_char(writer, '|');
	pqcp_sovereign_audit_writer_cef_header_text(
		writer, name);
	pqcp_sovereign_audit_writer_char(writer, '|');
	pqcp_sovereign_audit_writer_u64(writer, severity);
	pqcp_sovereign_audit_writer_char(writer, '|');
}

static void write_attribute(
	struct pqcp_sovereign_audit_writer *writer,
	bool *first,
	const struct pqcp_sovereign_audit_attribute *attribute)
{
	char key[
		sizeof("pqcp_") +
		PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_KEY_MAX_CHARS];
	size_t key_length;

	memset(key, 0, sizeof(key));
	memcpy(key, "pqcp_", 5U);
	key_length = strnlen(
		attribute->key, sizeof(attribute->key));
	memcpy(key + 5U, attribute->key, key_length);
	switch (attribute->type) {
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_U64:
		write_extension_u64(
			writer, first, key,
			attribute->value.u64);
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_I64:
		write_extension_i64(
			writer, first, key,
			attribute->value.i64);
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_BOOL:
		write_extension_bool(
			writer, first, key,
			attribute->value.boolean);
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT:
		write_extension_text(
			writer, first, key,
			attribute->value.text);
		break;
	case PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_DIGEST:
		write_extension_hex(
			writer, first, key,
			attribute->value.digest,
			sizeof(attribute->value.digest));
		break;
	default:
		break;
	}
}

static void write_event_extensions(
	struct pqcp_sovereign_audit_writer *writer,
	const struct pqcp_sovereign_event *event)
{
	bool first = true;

	write_extension_u64(
		writer, &first, "rt", event->observed_at_ms);
	write_extension_u64(
		writer, &first, "end", event->ingested_at_ms);
	write_extension_u64(
		writer, &first, "cn1", event->sequence);
	write_extension_text(
		writer, &first, "cn1Label", "eventSequence");
	write_extension_u64(
		writer, &first, "cn2", event->policy_epoch);
	write_extension_text(
		writer, &first, "cn2Label", "policyEpoch");
	write_extension_u64(
		writer, &first, "cn3", event->revocation_epoch);
	write_extension_text(
		writer, &first, "cn3Label", "revocationEpoch");
	write_extension_text(
		writer, &first, "suid", event->tenant.tenant_id);
	write_extension_text(
		writer, &first, "sourceServiceName",
		event->source);
	write_extension_text(
		writer, &first, "suser", event->actor);
	write_extension_text(
		writer, &first, "dobj", event->object);
	write_extension_text(
		writer, &first, "act", event->action);
	write_extension_text(
		writer, &first, "outcome",
		pqcp_sovereign_audit_outcome_str(
			event->outcome));
	write_extension_i64(
		writer, &first, "reasonCode",
		event->result);
	write_extension_text(
		writer, &first, "msg", event->reason);
	write_extension_u64(
		writer, &first, "externalId",
		event->correlation_id);
	write_extension_u64(
		writer, &first, "flexNumber1",
		event->flags);
	write_extension_text(
		writer, &first, "flexNumber1Label",
		"eventFlags");
	write_extension_u64(
		writer, &first, "flexNumber2",
		event->data_class);
	write_extension_text(
		writer, &first, "flexNumber2Label",
		"dataClass");
	write_extension_hex(
		writer, &first, "eventId",
		event->event_id, sizeof(event->event_id));
	write_extension_hex(
		writer, &first, "eventDigest",
		event->event_digest,
		sizeof(event->event_digest));
	write_extension_hex(
		writer, &first, "previousDigest",
		event->previous_digest,
		sizeof(event->previous_digest));
	write_extension_hex(
		writer, &first, "evidenceDigest",
		event->evidence_digest,
		sizeof(event->evidence_digest));
	write_extension_hex(
		writer, &first, "receiptDigest",
		event->receipt_digest,
		sizeof(event->receipt_digest));
	write_extension_hex(
		writer, &first, "resourceDigest",
		event->resource_digest,
		sizeof(event->resource_digest));
	for (size_t index = 0U;
	     index < event->attribute_count; ++index) {
		write_attribute(
			writer, &first,
			&event->attributes[index]);
	}
}

static void write_event(
	struct pqcp_sovereign_audit_writer *writer,
	const struct pqcp_sovereign_event *event)
{
	const char *class_name =
		pqcp_sovereign_audit_event_class_str(
			event->event_class);
	const char *activity_name =
		pqcp_sovereign_audit_activity_str(
			event->activity);

	write_syslog_prefix(
		writer, event->severity, class_name);
	write_cef_header(
		writer, class_name, activity_name,
		cef_severity(event->severity));
	write_event_extensions(writer, event);
}

int pqcp_sovereign_audit_cef_encode_event(
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

static void write_batch_summary(
	struct pqcp_sovereign_audit_writer *writer,
	const struct pqcp_sovereign_export_batch *batch)
{
	bool first = true;

	write_syslog_prefix(
		writer,
		PQCP_SOVEREIGN_AUDIT_SEVERITY_INFORMATIONAL,
		"audit_batch");
	write_cef_header(
		writer, "audit_batch", "export",
		cef_severity(
			PQCP_SOVEREIGN_AUDIT_SEVERITY_INFORMATIONAL));
	write_extension_u64(
		writer, &first, "rt", batch->created_at_ms);
	write_extension_u64(
		writer, &first, "externalId",
		batch->cursor_id);
	write_extension_text(
		writer, &first, "suid", batch->tenant_id);
	write_extension_u64(
		writer, &first, "cn1",
		batch->first_sequence);
	write_extension_text(
		writer, &first, "cn1Label",
		"firstSequence");
	write_extension_u64(
		writer, &first, "cn2",
		batch->last_sequence);
	write_extension_text(
		writer, &first, "cn2Label",
		"lastSequence");
	write_extension_u64(
		writer, &first, "cn3",
		batch->scanned_through_sequence);
	write_extension_text(
		writer, &first, "cn3Label",
		"scannedThroughSequence");
	write_extension_u64(
		writer, &first, "cnt", batch->event_count);
	write_extension_u64(
		writer, &first, "policyEpoch",
		batch->policy_epoch);
	write_extension_u64(
		writer, &first, "redactionPolicy",
		batch->redaction);
	write_extension_hex(
		writer, &first, "sourceAnchorDigest",
		batch->source_anchor_digest,
		sizeof(batch->source_anchor_digest));
	write_extension_hex(
		writer, &first, "sourceChainHead",
		batch->source_chain_head,
		sizeof(batch->source_chain_head));
	write_extension_hex(
		writer, &first, "previousBatchDigest",
		batch->previous_batch_digest,
		sizeof(batch->previous_batch_digest));
	write_extension_hex(
		writer, &first, "receiptDigest",
		batch->receipt_digest,
		sizeof(batch->receipt_digest));
	write_extension_hex(
		writer, &first, "batchDigest",
		batch->batch_digest,
		sizeof(batch->batch_digest));
	write_extension_u64(
		writer, &first, "signatureAlgorithm",
		batch->signature_algorithm);
	if (batch->signature_length != 0U) {
		write_extension_hex(
			writer, &first, "batchSignature",
			batch->signature,
			batch->signature_length);
	}
}

int pqcp_sovereign_audit_cef_encode_batch(
	const struct pqcp_sovereign_export_batch *batch,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	struct pqcp_sovereign_audit_writer writer;

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
	write_batch_summary(&writer, batch);
	for (size_t index = 0U;
	     index < batch->event_count; ++index) {
		pqcp_sovereign_audit_writer_char(
			&writer, '\n');
		write_event(&writer, &batch->events[index]);
	}
	return pqcp_sovereign_audit_writer_finish(
		&writer, output_length);
}
