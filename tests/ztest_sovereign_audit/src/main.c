/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Sovereign audit event, hash-chained ledger, and CBOR/CEF/OCSF exporter
 * contract tests.
 *
 * Source adapters and signed cross-plane export flows are in bridge.c.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/sovereign_audit.h>
#include <pqcp_zephyr/runtime_key_store.h>
#include <psa/crypto.h>

#include "../../../src/sovereign_audit_internal.h"

#define DIGEST_BYTES PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES
#define LEDGER_CAP_MAX 16U
#define OUT_CAPACITY 32768U
#define GUARD_BYTES 16U
#define GUARD_FILL 0xccU

/* ------------------------------------------------------------------ */
/* Shared fixtures                                                     */
/* ------------------------------------------------------------------ */

static struct pqcp_sovereign_event ledger_storage[LEDGER_CAP_MAX];
static struct pqcp_sovereign_event_ledger ledger;
static uint8_t anchor[DIGEST_BYTES];

static struct pqcp_sovereign_event batch_events[4];
static struct pqcp_sovereign_export_batch batch;

static uint8_t out_buf[OUT_CAPACITY];
static uint8_t ref_buf[OUT_CAPACITY];
static uint8_t guard_buf[OUT_CAPACITY + GUARD_BYTES];
static char scratch[4096];

typedef int (*encode_event_fn)(
	const struct pqcp_sovereign_event *event, uint8_t *output,
	size_t output_capacity, size_t *output_length);
typedef int (*encode_batch_fn)(
	const struct pqcp_sovereign_export_batch *batch, uint8_t *output,
	size_t output_capacity, size_t *output_length);

static void fill_digest(uint8_t digest[DIGEST_BYTES], uint8_t seed)
{
	memset(digest, seed, DIGEST_BYTES);
}

static void hex_encode(const uint8_t *bytes, size_t length, char *out)
{
	static const char hex[] = "0123456789abcdef";

	for (size_t index = 0U; index < length; ++index) {
		out[index * 2U] = hex[bytes[index] >> 4U];
		out[index * 2U + 1U] = hex[bytes[index] & 0x0fU];
	}
	out[length * 2U] = '\0';
}

static const char *find_bytes(const uint8_t *buffer, size_t length,
			      const char *needle)
{
	size_t needle_length = strlen(needle);

	if (needle_length == 0U || needle_length > length) {
		return NULL;
	}
	for (size_t index = 0U; index + needle_length <= length; ++index) {
		if (memcmp(buffer + index, needle, needle_length) == 0) {
			return (const char *)(buffer + index);
		}
	}
	return NULL;
}

static const uint8_t *find_raw(const uint8_t *buffer, size_t length,
			       const uint8_t *needle, size_t needle_length)
{
	if (needle_length == 0U || needle_length > length) {
		return NULL;
	}
	for (size_t index = 0U; index + needle_length <= length; ++index) {
		if (memcmp(buffer + index, needle, needle_length) == 0) {
			return buffer + index;
		}
	}
	return NULL;
}

static bool has(const uint8_t *buffer, size_t length, const char *needle)
{
	return find_bytes(buffer, length, needle) != NULL;
}

static size_t count_of(const uint8_t *buffer, size_t length,
		       const char *needle)
{
	size_t needle_length = strlen(needle);
	size_t total = 0U;

	for (size_t index = 0U; index + needle_length <= length; ++index) {
		if (memcmp(buffer + index, needle, needle_length) == 0) {
			total++;
		}
	}
	return total;
}

static size_t count_byte(const uint8_t *buffer, size_t length, uint8_t value)
{
	size_t total = 0U;

	for (size_t index = 0U; index < length; ++index) {
		if (buffer[index] == value) {
			total++;
		}
	}
	return total;
}

static void make_str(char *buffer, size_t length)
{
	memset(buffer, 'a', length);
	buffer[length] = '\0';
}

/* Minimal strict JSON validator (objects, arrays, strings, ints, literals). */
struct json_parser {
	const uint8_t *data;
	size_t length;
	size_t index;
	unsigned int depth;
};

static void json_ws(struct json_parser *parser)
{
	while (parser->index < parser->length &&
	       (parser->data[parser->index] == ' ' ||
		parser->data[parser->index] == '\n' ||
		parser->data[parser->index] == '\t' ||
		parser->data[parser->index] == '\r')) {
		parser->index++;
	}
}

static bool json_string(struct json_parser *parser)
{
	if (parser->index >= parser->length ||
	    parser->data[parser->index] != '"') {
		return false;
	}
	parser->index++;
	while (parser->index < parser->length) {
		uint8_t value = parser->data[parser->index++];

		if (value == '"') {
			return true;
		}
		if (value < 0x20U) {
			return false;
		}
		if (value == '\\') {
			if (parser->index >= parser->length) {
				return false;
			}
			value = parser->data[parser->index++];
			if (value == 'u') {
				for (size_t digit = 0U; digit < 4U; ++digit) {
					uint8_t hexc;

					if (parser->index >= parser->length) {
						return false;
					}
					hexc = parser->data[parser->index++];
					if (!((hexc >= '0' && hexc <= '9') ||
					      (hexc >= 'a' && hexc <= 'f') ||
					      (hexc >= 'A' && hexc <= 'F'))) {
						return false;
					}
				}
			} else if (strchr("\"\\/bfnrt", (char)value) == NULL) {
				return false;
			}
		}
	}
	return false;
}

static bool json_value(struct json_parser *parser);

static bool json_literal(struct json_parser *parser, const char *literal)
{
	size_t length = strlen(literal);

	if (parser->index + length > parser->length ||
	    memcmp(parser->data + parser->index, literal, length) != 0) {
		return false;
	}
	parser->index += length;
	return true;
}

static bool json_value(struct json_parser *parser)
{
	bool ok = false;

	json_ws(parser);
	if (parser->index >= parser->length || parser->depth > 16U) {
		return false;
	}
	switch (parser->data[parser->index]) {
	case '{':
		parser->depth++;
		parser->index++;
		json_ws(parser);
		if (parser->index < parser->length &&
		    parser->data[parser->index] == '}') {
			parser->index++;
			ok = true;
			parser->depth--;
			return ok;
		}
		for (;;) {
			json_ws(parser);
			if (!json_string(parser)) {
				return false;
			}
			json_ws(parser);
			if (parser->index >= parser->length ||
			    parser->data[parser->index++] != ':') {
				return false;
			}
			if (!json_value(parser)) {
				return false;
			}
			json_ws(parser);
			if (parser->index >= parser->length) {
				return false;
			}
			if (parser->data[parser->index] == ',') {
				parser->index++;
				continue;
			}
			if (parser->data[parser->index] == '}') {
				parser->index++;
				parser->depth--;
				return true;
			}
			return false;
		}
	case '[':
		parser->depth++;
		parser->index++;
		json_ws(parser);
		if (parser->index < parser->length &&
		    parser->data[parser->index] == ']') {
			parser->index++;
			parser->depth--;
			return true;
		}
		for (;;) {
			if (!json_value(parser)) {
				return false;
			}
			json_ws(parser);
			if (parser->index >= parser->length) {
				return false;
			}
			if (parser->data[parser->index] == ',') {
				parser->index++;
				continue;
			}
			if (parser->data[parser->index] == ']') {
				parser->index++;
				parser->depth--;
				return true;
			}
			return false;
		}
	case '"':
		return json_string(parser);
	case 't':
		return json_literal(parser, "true");
	case 'f':
		return json_literal(parser, "false");
	case 'n':
		return json_literal(parser, "null");
	default: {
		size_t digits = 0U;

		if (parser->data[parser->index] == '-') {
			parser->index++;
		}
		while (parser->index < parser->length &&
		       parser->data[parser->index] >= '0' &&
		       parser->data[parser->index] <= '9') {
			parser->index++;
			digits++;
		}
		return digits != 0U;
	}
	}
}

static bool json_valid(const uint8_t *data, size_t length)
{
	struct json_parser parser = { .data = data, .length = length };

	if (!json_value(&parser)) {
		return false;
	}
	json_ws(&parser);
	return parser.index == parser.length;
}

/* Draft/event builders. */
static uint8_t d_actor[DIGEST_BYTES];
static uint8_t d_subject[DIGEST_BYTES];
static uint8_t d_resource[DIGEST_BYTES];
static uint8_t d_evidence[DIGEST_BYTES];
static uint8_t d_receipt[DIGEST_BYTES];

static void fill_draft(struct pqcp_sovereign_event_draft *draft, uint64_t n)
{
	fill_digest(d_actor, 0x01U);
	fill_digest(d_subject, 0x02U);
	fill_digest(d_resource, 0x03U);
	fill_digest(d_evidence, 0x04U);
	fill_digest(d_receipt, 0x05U);
	memset(draft, 0, sizeof(*draft));
	draft->tenant_id = "tenant-a";
	draft->realm = "eu";
	draft->source = "unit";
	draft->actor = "alice";
	draft->object = "key/1";
	draft->action = "sign";
	draft->reason = "because";
	draft->event_class = PQCP_SOVEREIGN_AUDIT_CLASS_DEPLOYMENT;
	draft->activity = PQCP_SOVEREIGN_AUDIT_ACTIVITY_DEPLOY;
	draft->severity = PQCP_SOVEREIGN_AUDIT_SEVERITY_HIGH;
	draft->outcome = PQCP_SOVEREIGN_AUDIT_OUTCOME_SUCCESS;
	draft->data_class = PQCP_SOVEREIGN_AUDIT_DATA_CONFIDENTIAL;
	draft->observed_at_ms = 1000U + n;
	draft->ingested_at_ms = 1005U + n;
	draft->expires_at_ms = 0U;
	draft->correlation_id = 4242U + n;
	draft->policy_epoch = 7U;
	draft->revocation_epoch = 3U;
	draft->flags = PQCP_SOVEREIGN_AUDIT_EVENT_SECURITY_RELEVANT |
		       PQCP_SOVEREIGN_AUDIT_EVENT_REGULATORY;
	draft->result = 0;
	draft->actor_digest = d_actor;
	draft->subject_digest = d_subject;
	draft->resource_digest = d_resource;
	draft->evidence_digest = d_evidence;
	draft->receipt_digest = d_receipt;
}

static void make_event(struct pqcp_sovereign_event *event, uint64_t n)
{
	struct pqcp_sovereign_event_draft draft;

	fill_draft(&draft, n);
	zassert_ok(pqcp_sovereign_event_init(event, &draft), "init");
}

static void add_rich_attributes(struct pqcp_sovereign_event *event)
{
	uint8_t digest[DIGEST_BYTES];

	fill_digest(digest, 0x11U);
	zassert_ok(pqcp_sovereign_event_add_u64(event, "a_u64", 42U, 0U));
	zassert_ok(pqcp_sovereign_event_add_i64(event, "b_i64", -7, 0U));
	zassert_ok(pqcp_sovereign_event_add_bool(event, "c_bool", true, 0U));
	zassert_ok(pqcp_sovereign_event_add_text(event, "d_text", "x=1|y\\z", 0U));
	zassert_ok(pqcp_sovereign_event_add_digest(event, "e_digest", digest, 0U));
}

static void reset_ledger(size_t capacity, uint64_t first_sequence)
{
	zassert_true(capacity <= LEDGER_CAP_MAX);
	memset(anchor, 0xa5, sizeof(anchor));
	zassert_ok(pqcp_sovereign_event_ledger_init(
		&ledger, ledger_storage, capacity, first_sequence, anchor));
}

/* Append events n = start .. start + count - 1; last committed -> *last. */
static void append_events(uint64_t start, size_t count,
			  struct pqcp_sovereign_event *last)
{
	for (size_t index = 0U; index < count; ++index) {
		struct pqcp_sovereign_event event;
		struct pqcp_sovereign_event committed;

		make_event(&event, start + index);
		zassert_ok(pqcp_sovereign_event_ledger_append(
			&ledger, &event, &committed), "append");
		if (last != NULL) {
			*last = committed;
		}
	}
}

static struct pqcp_sovereign_event *physical_event(uint64_t sequence)
{
	for (size_t index = 0U; index < ledger.capacity; ++index) {
		if (ledger.events[index].occupied &&
		    ledger.events[index].sequence == sequence) {
			return &ledger.events[index];
		}
	}
	return NULL;
}

static void *suite_setup(void)
{
	return NULL;
}

static void before_case(void *fixture)
{
	ARG_UNUSED(fixture);
	memset(&batch, 0, sizeof(batch));
	memset(batch_events, 0, sizeof(batch_events));
	reset_ledger(8U, 1U);
}

/* Build a batch referring to events 1..count of the current ledger. */
static void build_batch(size_t count, enum pqcp_sovereign_audit_format format)
{
	memset(&batch, 0, sizeof(batch));
	zassert_true(count >= 1U && count <= ARRAY_SIZE(batch_events));
	for (size_t index = 0U; index < count; ++index) {
		zassert_ok(pqcp_sovereign_event_ledger_get(
			&ledger, 1U + index, &batch_events[index]));
	}
	batch.schema_version = PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION;
	batch.cursor_id = 77U;
	batch.created_at_ms = 2000U;
	batch.policy_epoch = 7U;
	batch.first_sequence = 1U;
	batch.last_sequence = count;
	batch.scanned_through_sequence = count;
	batch.event_count = (uint32_t)count;
	batch.format = format;
	batch.redaction = PQCP_SOVEREIGN_AUDIT_REDACTION_NONE;
	strcpy(batch.tenant_id, "tenant-a");
	fill_digest(batch.source_anchor_digest, 0x21U);
	fill_digest(batch.source_chain_head, 0x22U);
	fill_digest(batch.previous_batch_digest, 0x23U);
	fill_digest(batch.receipt_digest, 0x24U);
	fill_digest(batch.batch_digest, 0x25U);
	batch.signature_algorithm = PQCP_SOVEREIGN_AUDIT_SIGNATURE_NONE;
	batch.signature_length = 0U;
	batch.events = batch_events;
	batch.complete = true;
	batch.resumed = false;
}

/*
 * Exhaustively check that every capacity below the exact encoded length fails
 * with -ENOSPC without writing past the stated capacity, and that the exact
 * length succeeds and reproduces the reference bytes.
 */
static size_t sweep_output_capacities(
	const uint8_t *reference, size_t length,
	int (*run)(const void *subject, uint8_t *output, size_t capacity,
		   size_t *produced),
	const void *subject, size_t stride)
{
	size_t produced = 0U;
	int ret;

	/* exact size */
	memset(guard_buf, GUARD_FILL, length + GUARD_BYTES + 1U);
	ret = run(subject, guard_buf, length, &produced);
	zassert_ok(ret, "exact-size encode failed: %d", ret);
	zassert_equal(produced, length);
	zassert_mem_equal(guard_buf, reference, length);
	for (size_t index = length; index < length + GUARD_BYTES; ++index) {
		zassert_equal(guard_buf[index], GUARD_FILL,
			      "write past exact capacity at %zu", index);
	}

	/* capacity one larger than needed: same output, same length */
	memset(guard_buf, GUARD_FILL, length + GUARD_BYTES + 1U);
	ret = run(subject, guard_buf, length + 1U, &produced);
	zassert_ok(ret);
	zassert_equal(produced, length);
	zassert_mem_equal(guard_buf, reference, length);

	/* size - 1 and a sweep of smaller capacities */
	for (size_t capacity = length - 1U; capacity >= 1U;
	     capacity = capacity > stride ? capacity - stride : 0U) {
		memset(guard_buf, GUARD_FILL, length + GUARD_BYTES + 1U);
		produced = 0x1234U;
		ret = run(subject, guard_buf, capacity, &produced);
		zassert_equal(ret, -ENOSPC,
			      "capacity %zu of %zu returned %d", capacity,
			      length, ret);
		zassert_equal(produced, 0U, "length leaked on failure");
		for (size_t index = capacity; index < capacity + GUARD_BYTES;
		     ++index) {
			zassert_equal(guard_buf[index], GUARD_FILL,
				      "overrun at %zu (cap %zu)", index,
				      capacity);
		}
		if (capacity == 0U) {
			break;
		}
	}
	return length;
}

struct event_run {
	encode_event_fn fn;
	const struct pqcp_sovereign_event *event;
};

static int run_event(const void *subject, uint8_t *output, size_t capacity,
		     size_t *produced)
{
	const struct event_run *run = subject;

	return run->fn(run->event, output, capacity, produced);
}

struct batch_run {
	encode_batch_fn fn;
	const struct pqcp_sovereign_export_batch *batch;
};

static int run_batch(const void *subject, uint8_t *output, size_t capacity,
		     size_t *produced)
{
	const struct batch_run *run = subject;

	return run->fn(run->batch, output, capacity, produced);
}

static size_t event_boundaries(encode_event_fn fn,
			       const struct pqcp_sovereign_event *event,
			       size_t stride)
{
	struct event_run run = { .fn = fn, .event = event };
	size_t length = 0U;

	zassert_ok(fn(event, out_buf, sizeof(out_buf), &length));
	zassert_true(length > 1U);
	memcpy(ref_buf, out_buf, length);
	/* deterministic */
	{
		size_t second = 0U;

		zassert_ok(fn(event, out_buf, sizeof(out_buf), &second));
		zassert_equal(second, length);
		zassert_mem_equal(out_buf, ref_buf, length);
	}
	return sweep_output_capacities(ref_buf, length, run_event, &run, stride);
}

static size_t batch_boundaries(encode_batch_fn fn,
			       const struct pqcp_sovereign_export_batch *b,
			       size_t stride)
{
	struct batch_run run = { .fn = fn, .batch = b };
	size_t length = 0U;

	zassert_ok(fn(b, out_buf, sizeof(out_buf), &length));
	zassert_true(length > 1U);
	memcpy(ref_buf, out_buf, length);
	return sweep_output_capacities(ref_buf, length, run_batch, &run, stride);
}

/* Common negative checks shared by all three single-event encoders. */
static void event_encoder_negatives(encode_event_fn fn)
{
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event fresh;
	size_t length = 99U;

	append_events(0U, 1U, &event);

	zassert_equal(fn(NULL, out_buf, sizeof(out_buf), &length), -EINVAL);
	zassert_equal(fn(&event, NULL, sizeof(out_buf), &length), -EINVAL);
	zassert_equal(fn(&event, out_buf, 0U, &length), -EINVAL);
	zassert_equal(fn(&event, out_buf, sizeof(out_buf), NULL), -EINVAL);

	/* An event that has not been committed to a ledger is not occupied. */
	make_event(&fresh, 0U);
	zassert_equal(fn(&fresh, out_buf, sizeof(out_buf), &length), -EINVAL);

	{
		struct pqcp_sovereign_event bad = event;

		bad.schema_version = PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION + 1U;
		zassert_equal(fn(&bad, out_buf, sizeof(out_buf), &length),
			      -EINVAL);
	}
	{
		struct pqcp_sovereign_event bad = event;

		bad.attribute_count = PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES + 1U;
		zassert_equal(fn(&bad, out_buf, sizeof(out_buf), &length),
			      -EINVAL);
	}
}

static void batch_encoder_negatives(encode_batch_fn fn)
{
	size_t length = 99U;
	struct pqcp_sovereign_export_batch bad;

	append_events(0U, 2U, NULL);
	build_batch(2U, PQCP_SOVEREIGN_AUDIT_FORMAT_CEF_SYSLOG);

	zassert_equal(fn(NULL, out_buf, sizeof(out_buf), &length), -EINVAL);
	zassert_equal(fn(&batch, NULL, sizeof(out_buf), &length), -EINVAL);
	zassert_equal(fn(&batch, out_buf, 0U, &length), -EINVAL);
	zassert_equal(fn(&batch, out_buf, sizeof(out_buf), NULL), -EINVAL);

	bad = batch;
	bad.schema_version = 2U;
	zassert_equal(fn(&bad, out_buf, sizeof(out_buf), &length), -EINVAL);
	bad = batch;
	bad.event_count = 0U;
	zassert_equal(fn(&bad, out_buf, sizeof(out_buf), &length), -EINVAL);
	bad = batch;
	bad.events = NULL;
	zassert_equal(fn(&bad, out_buf, sizeof(out_buf), &length), -EINVAL);
	bad = batch;
	bad.signature_length = sizeof(bad.signature) + 1U;
	zassert_equal(fn(&bad, out_buf, sizeof(out_buf), &length), -EINVAL);
}

ZTEST_SUITE(pqcp_sovereign_audit, NULL, suite_setup, before_case, NULL, NULL);

static struct pqcp_sovereign_audit_exporter exporter;
static struct pqcp_sovereign_audit_cursor export_cursors[2];
static struct pqcp_sovereign_event export_workspace[2];
static struct pqcp_sovereign_audit_export_policy export_policy;
static struct pqcp_sovereign_audit_export_config export_config;
static const struct pqcp_sovereign_audit_export_storage export_storage = {
	.cursors = export_cursors,
	.cursor_capacity = ARRAY_SIZE(export_cursors),
	.workspace_events = export_workspace,
	.workspace_event_capacity = ARRAY_SIZE(export_workspace),
};

static void reset_exporter(void)
{
	memset(&export_config, 0, sizeof(export_config));
	export_config.maximum_cursor_lifetime_ms = 10000U;
	export_config.maximum_batch_events = 2U;
	memset(&export_policy, 0, sizeof(export_policy));
	strcpy(export_policy.tenant_id, "tenant-a");
	export_policy.policy_epoch = 7U;
	export_policy.maximum_events = 2U;
	export_policy.maximum_data_class = PQCP_SOVEREIGN_AUDIT_DATA_SECRET;
	export_policy.include_attributes = true;
	export_policy.include_reasons = true;
	zassert_ok(pqcp_sovereign_audit_exporter_init(
		&exporter, &ledger, &export_config, &export_storage));
}

static uint64_t open_export(void)
{
	uint64_t id = 0U;

	zassert_ok(pqcp_sovereign_audit_export_open(
		&exporter, "consumer", "tenant-a", 0U, 2000U, 9000U, 7U, &id));
	return id;
}

static int prepare_export(uint64_t id, uint64_t now)
{
	return pqcp_sovereign_audit_export_prepare(&exporter, id, &export_policy,
		now, out_buf, sizeof(out_buf), &batch);
}

ZTEST(pqcp_sovereign_audit, test_export_exact_ack_and_chained_batches)
{
	uint8_t digest[DIGEST_BYTES];

	append_events(0U, 3U, NULL);
	reset_exporter();
	uint64_t id = open_export();

	zassert_ok(prepare_export(id, 2001U));
	zassert_equal(batch.event_count, 2U);
	zassert_equal(batch.first_sequence, 1U);
	zassert_equal(batch.last_sequence, 2U);
	zassert_false(batch.complete);
	zassert_false(batch.resumed);
	memcpy(digest, batch.batch_digest, sizeof(digest));
	digest[0] ^= 1U;
	zassert_equal(pqcp_sovereign_audit_export_acknowledge(
		&exporter, id, 1U, 2U, digest, 2002U), -EBADMSG);
	digest[0] ^= 1U;
	zassert_equal(pqcp_sovereign_audit_export_acknowledge(
		&exporter, id, 1U, 3U, digest, 2002U), -EBADMSG);
	zassert_equal(export_cursors[0].next_sequence, 1U);
	zassert_ok(pqcp_sovereign_audit_exporter_audit(&exporter));
	zassert_ok(pqcp_sovereign_audit_export_acknowledge(
		&exporter, id, 1U, 2U, digest, 2002U));
	zassert_equal(pqcp_sovereign_audit_export_acknowledge(
		&exporter, id, 1U, 2U, digest, 2002U), -EBADMSG);
	zassert_ok(prepare_export(id, 2003U));
	zassert_equal(batch.event_count, 1U);
	zassert_equal(batch.first_sequence, 3U);
	zassert_true(batch.complete);
	zassert_mem_equal(batch.previous_batch_digest, digest, sizeof(digest));
	zassert_ok(pqcp_sovereign_audit_exporter_audit(&exporter));
}

ZTEST(pqcp_sovereign_audit, test_export_retry_freezes_bytes_after_eviction)
{
	append_events(0U, 2U, NULL);
	reset_exporter();
	uint64_t id = open_export();

	zassert_ok(prepare_export(id, 2001U));
	size_t length = batch.encoded_length;

	memcpy(ref_buf, out_buf, length);
	append_events(10U, 10U, NULL);
	zassert_ok(prepare_export(id, 2050U));
	zassert_true(batch.resumed);
	zassert_equal(batch.created_at_ms, 2001U);
	zassert_equal(batch.encoded_length, length);
	zassert_mem_equal(out_buf, ref_buf, length);
	export_policy.include_reasons = false;
	zassert_equal(prepare_export(id, 2051U), -ESTALE);
	export_policy.include_reasons = true;
	zassert_ok(prepare_export(id, 2052U));
	zassert_ok(pqcp_sovereign_audit_exporter_audit(&exporter));
}

ZTEST(pqcp_sovereign_audit, test_export_tenant_filters_and_redaction)
{
	struct pqcp_sovereign_event_draft draft;
	struct pqcp_sovereign_event event;

	fill_draft(&draft, 0U);
	draft.tenant_id = "tenant-b";
	zassert_ok(pqcp_sovereign_event_init(&event, &draft));
	zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event, NULL));
	make_event(&event, 1U);
	add_rich_attributes(&event);
	zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event, NULL));
	reset_exporter();
	uint64_t id = open_export();

	strcpy(export_policy.tenant_id, "tenant-b");
	zassert_equal(prepare_export(id, 2001U), -EACCES);
	strcpy(export_policy.tenant_id, "tenant-a");
	export_policy.policy_epoch++;
	zassert_equal(prepare_export(id, 2001U), -EACCES);
	export_policy.policy_epoch--;
	strcpy(export_policy.realm, "us");
	zassert_equal(prepare_export(id, 2001U), -ENOENT);
	strcpy(export_policy.realm, "eu");
	export_policy.redaction = PQCP_SOVEREIGN_AUDIT_REDACTION_STRICT;
	export_policy.include_attributes = false;
	export_policy.include_reasons = false;
	export_policy.format = PQCP_SOVEREIGN_AUDIT_FORMAT_OCSF_JSON;
	zassert_ok(prepare_export(id, 2002U));
	zassert_equal(batch.first_sequence, 2U);
	zassert_equal(batch.event_count, 1U);
	zassert_equal(batch.events[0].attribute_count, 0U);
	zassert_is_null(find_bytes(out_buf, batch.encoded_length, "alice"));
	zassert_is_null(find_bytes(out_buf, batch.encoded_length, "because"));
	zassert_is_null(find_bytes(out_buf, batch.encoded_length, "tenant-b"));
	/* A projection retains its source commitment; the batch authenticates
	 * the redacted representation separately.
	 */
	zassert_mem_equal(batch.events[0].event_digest, physical_event(2U)->event_digest, DIGEST_BYTES);
	zassert_ok(pqcp_sovereign_audit_exporter_audit(&exporter));
	zassert_ok(prepare_export(id, 2003U));
}

ZTEST(pqcp_sovereign_audit, test_export_policy_masks_flags_and_classification)
{
	append_events(0U, 1U, NULL);
	reset_exporter();
	uint64_t id = open_export();

	export_policy.class_mask = 1ULL << PQCP_SOVEREIGN_AUDIT_CLASS_CRYPTO_OPERATION;
	zassert_equal(prepare_export(id, 2001U), -ENOENT);
	export_policy.class_mask = 1ULL << PQCP_SOVEREIGN_AUDIT_CLASS_DEPLOYMENT;
	export_policy.activity_mask = 1ULL << PQCP_SOVEREIGN_AUDIT_ACTIVITY_READ;
	zassert_equal(prepare_export(id, 2001U), -ENOENT);
	export_policy.activity_mask = 1ULL << PQCP_SOVEREIGN_AUDIT_ACTIVITY_DEPLOY;
	export_policy.minimum_severity = PQCP_SOVEREIGN_AUDIT_SEVERITY_CRITICAL;
	zassert_equal(prepare_export(id, 2001U), -ENOENT);
	export_policy.minimum_severity = PQCP_SOVEREIGN_AUDIT_SEVERITY_HIGH;
	export_policy.maximum_data_class = PQCP_SOVEREIGN_AUDIT_DATA_PUBLIC;
	zassert_equal(prepare_export(id, 2001U), -ENOENT);
	export_policy.maximum_data_class = PQCP_SOVEREIGN_AUDIT_DATA_CONFIDENTIAL;
	export_policy.forbidden_flags = PQCP_SOVEREIGN_AUDIT_EVENT_REGULATORY;
	zassert_equal(prepare_export(id, 2001U), -ENOENT);
	export_policy.forbidden_flags = 0U;
	export_policy.required_flags = PQCP_SOVEREIGN_AUDIT_EVENT_CHECKPOINT;
	zassert_equal(prepare_export(id, 2001U), -ENOENT);
	export_policy.required_flags = PQCP_SOVEREIGN_AUDIT_EVENT_REGULATORY;
	zassert_ok(prepare_export(id, 2001U));
}

ZTEST(pqcp_sovereign_audit, test_export_small_buffer_never_commits_or_drops_retry)
{
	append_events(0U, 1U, NULL);
	reset_exporter();
	uint64_t id = open_export();

	zassert_equal(pqcp_sovereign_audit_export_prepare(&exporter, id, &export_policy,
		2001U, out_buf, 1U, &batch), -ENOSPC);
	zassert_equal(out_buf[0], 0U);
	zassert_equal(batch.encoded_length, 0U);
	zassert_equal(export_cursors[0].state, PQCP_SOVEREIGN_AUDIT_CURSOR_ACTIVE);
	zassert_equal(exporter.pending_batch.cursor_id, 0U);
	zassert_ok(prepare_export(id, 2002U));
	size_t length = batch.encoded_length;

	memcpy(ref_buf, out_buf, length);
	zassert_equal(pqcp_sovereign_audit_export_prepare(&exporter, id, &export_policy,
		2003U, out_buf, 1U, &batch), -ENOSPC);
	zassert_ok(prepare_export(id, 2004U));
	zassert_mem_equal(out_buf, ref_buf, length);
}

ZTEST(pqcp_sovereign_audit, test_export_shared_workspace_close_and_expiry)
{
	uint32_t expired = 0U;

	append_events(0U, 1U, NULL);
	reset_exporter();
	uint64_t a = open_export();
	uint64_t b = open_export();
	uint64_t third = 0U;

	zassert_equal(pqcp_sovereign_audit_export_open(&exporter, "third", "tenant-a",
		0U, 2000U, 9000U, 7U, &third), -ENOSPC);
	zassert_ok(prepare_export(a, 2001U));
	zassert_equal(prepare_export(b, 2002U), -EBUSY);
	zassert_ok(pqcp_sovereign_audit_export_close(&exporter, a));
	zassert_ok(prepare_export(b, 2003U));
	zassert_equal(prepare_export(a, 2004U), -ENOENT);
	zassert_equal(prepare_export(b, 9000U), -ETIMEDOUT);
	zassert_ok(pqcp_sovereign_audit_export_expire(&exporter, 9000U, &expired));
	zassert_equal(expired, 1U);
	zassert_equal(exporter.pending_batch.cursor_id, 0U);
	zassert_mem_equal(export_workspace, (uint8_t[sizeof(export_workspace)]){0}, sizeof(export_workspace));
	zassert_ok(pqcp_sovereign_audit_exporter_audit(&exporter));
	uint64_t replacement = open_export();

	zassert_true(replacement > b);
	zassert_ok(prepare_export(replacement, 2001U));
}

ZTEST(pqcp_sovereign_audit, test_export_rejects_evicted_and_corrupt_history)
{
	reset_exporter();
	uint64_t id = open_export();

	zassert_equal(prepare_export(id, 2001U), -ENOENT);
	append_events(0U, 10U, NULL);
	zassert_equal(prepare_export(id, 2002U), -ESTALE);
	zassert_ok(pqcp_sovereign_audit_export_close(&exporter, id));
	id = open_export();
	physical_event(3U)->reason[0] ^= 1U;
	zassert_not_equal(prepare_export(id, 2003U), 0);
	zassert_equal(exporter.pending_batch.cursor_id, 0U);
}

ZTEST(pqcp_sovereign_audit, test_export_all_formats_and_unsupported_signature)
{
	append_events(0U, 1U, NULL);
	for (unsigned int format = 0U; format <= PQCP_SOVEREIGN_AUDIT_FORMAT_OCSF_JSON; ++format) {
		reset_exporter();
		uint64_t id = open_export();

		export_policy.require_signature = true;
		zassert_equal(prepare_export(id, 2001U), -ENOTSUP);
		export_policy.require_signature = false;
		export_policy.format = (enum pqcp_sovereign_audit_format)format;
		zassert_ok(prepare_export(id, 2002U));
		zassert_true(batch.encoded_length > 0U);
		zassert_equal(batch.format, format);
		zassert_equal(batch.signature_length, 0U);
	}
}

ZTEST(pqcp_sovereign_audit, test_export_empty_realm_is_included_by_wildcard)
{
	struct pqcp_sovereign_event_draft draft;
	struct pqcp_sovereign_event event;

	fill_draft(&draft, 0U);
	draft.realm = "";
	zassert_ok(pqcp_sovereign_event_init(&event, &draft));
	zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event, NULL));
	reset_exporter();
	uint64_t id = open_export();

	zassert_ok(prepare_export(id, 2001U));
	zassert_equal(batch.event_count, 1U);
}

ZTEST(pqcp_sovereign_audit, test_export_invalid_policy_time_and_exhaustion)
{
	reset_exporter();
	uint64_t id = open_export();

	zassert_equal(prepare_export(id, 1999U), -EINVAL);
	export_policy.format = (enum pqcp_sovereign_audit_format)-1;
	zassert_equal(prepare_export(id, 2001U), -EINVAL);
	export_policy.format = PQCP_SOVEREIGN_AUDIT_FORMAT_CBOR;
	export_policy.activity_mask = 1ULL << 63U;
	zassert_equal(prepare_export(id, 2001U), -EINVAL);
	export_policy.activity_mask = 0U;
	export_policy.required_flags = 1U << 31U;
	zassert_equal(prepare_export(id, 2001U), -EINVAL);
	export_policy.required_flags = 0U;
	export_policy.maximum_events = 0U;
	zassert_equal(prepare_export(id, 2001U), -EINVAL);
	exporter.next_cursor_id = UINT64_MAX;
	zassert_equal(pqcp_sovereign_audit_export_open(&exporter, "c", "tenant-a",
		0U, 2000U, 9000U, 7U, &id), -EOVERFLOW);
	exporter.next_cursor_id = 2U;
	zassert_equal(pqcp_sovereign_audit_export_open(&exporter, "c", "tenant-a",
		0U, 2000U, 12001U, 7U, &id), -ERANGE);
	export_config.signature_required = true;
	zassert_equal(pqcp_sovereign_audit_exporter_init(&exporter, &ledger,
		&export_config, &export_storage), -EINVAL);
}

ZTEST(pqcp_sovereign_audit, test_export_audit_detects_cursor_corruption)
{
	append_events(0U, 1U, NULL);
	reset_exporter();
	uint64_t id = open_export();

	zassert_ok(prepare_export(id, 2001U));
	export_cursors[0].outstanding_batch_digest[0] ^= 1U;
	zassert_equal(pqcp_sovereign_audit_exporter_audit(&exporter), -EBADMSG);
	export_cursors[0].outstanding_batch_digest[0] ^= 1U;
	zassert_ok(pqcp_sovereign_audit_exporter_audit(&exporter));
	export_cursors[0].next_sequence++;
	zassert_equal(pqcp_sovereign_audit_exporter_audit(&exporter), -EBADMSG);
}

ZTEST(pqcp_sovereign_audit, test_export_frozen_state_tamper_cannot_be_retried_or_acked)
{
	append_events(0U, 1U, NULL);
	reset_exporter();
	uint64_t id = open_export();

	zassert_ok(prepare_export(id, 2002U));
	uint8_t digest[DIGEST_BYTES];

	memcpy(digest, batch.batch_digest, sizeof(digest));
	export_workspace[0].reason[0] ^= 1U;
	zassert_equal(prepare_export(id, 2003U), -EBADMSG);
	zassert_equal(pqcp_sovereign_audit_exporter_audit(&exporter), -EBADMSG);
	zassert_equal(pqcp_sovereign_audit_export_acknowledge(
		&exporter, id, 1U, 1U, digest, 2003U), -EBADMSG);
	export_workspace[0].reason[0] ^= 1U;
	exporter.pending_batch.source_chain_head[0] ^= 1U;
	zassert_equal(prepare_export(id, 2003U), -EBADMSG);
	zassert_equal(pqcp_sovereign_audit_exporter_audit(&exporter), -EBADMSG);
	exporter.pending_batch.source_chain_head[0] ^= 1U;
	export_cursors[0].outstanding_scanned_sequence++;
	zassert_equal(pqcp_sovereign_audit_export_acknowledge(
		&exporter, id, 1U, 1U, digest, 2003U), -EBADMSG);
	export_cursors[0].outstanding_scanned_sequence--;
	zassert_ok(prepare_export(id, 2003U));
	zassert_ok(pqcp_sovereign_audit_exporter_audit(&exporter));
}

ZTEST(pqcp_sovereign_audit, test_export_no_time_rollback_or_buffer_alias)
{
	append_events(0U, 1U, NULL);
	reset_exporter();
	uint64_t id = open_export();

	zassert_ok(prepare_export(id, 2002U));
	uint8_t digest[DIGEST_BYTES];

	memcpy(digest, batch.batch_digest, sizeof(digest));
	zassert_equal(prepare_export(id, 2001U), -EINVAL);
	zassert_equal(pqcp_sovereign_audit_export_acknowledge(
		&exporter, id, 1U, 1U, digest, 2001U), -EINVAL);
	zassert_equal(pqcp_sovereign_audit_export_prepare(&exporter, id, &export_policy,
		2003U, (uint8_t *)export_workspace, sizeof(export_workspace), &batch), -EINVAL);
	zassert_ok(prepare_export(id, 2003U));
	zassert_equal(pqcp_sovereign_audit_export_acknowledge(
		&exporter, id, 1U, 1U, digest, 9000U), -ETIMEDOUT);
}

ZTEST(pqcp_sovereign_audit, test_export_digest_binds_canonical_projection_and_domain)
{
	psa_hash_operation_t hash = PSA_HASH_OPERATION_INIT;
	uint8_t expected[DIGEST_BYTES];
	size_t body_length, hash_length;
	static const uint8_t domain[] = "PQCP-SOVEREIGN-AUDIT-BATCH-V1";

	append_events(0U, 1U, NULL);
	reset_exporter();
	export_policy.redaction = PQCP_SOVEREIGN_AUDIT_REDACTION_STRICT;
	export_policy.include_reasons = false;
	uint64_t id = open_export();

	zassert_ok(prepare_export(id, 2002U));
	zassert_ok(pqcp_sovereign_audit_cbor_encode_batch_body(
		&batch, ref_buf, sizeof(ref_buf), &body_length));
	zassert_equal(psa_hash_setup(&hash, PSA_ALG_SHA_256), PSA_SUCCESS);
	zassert_equal(psa_hash_update(&hash, domain, sizeof(domain) - 1U), PSA_SUCCESS);
	zassert_equal(psa_hash_update(&hash, ref_buf, body_length), PSA_SUCCESS);
	zassert_equal(psa_hash_finish(&hash, expected, sizeof(expected), &hash_length), PSA_SUCCESS);
	zassert_equal(hash_length, DIGEST_BYTES);
	zassert_mem_equal(expected, batch.batch_digest, sizeof(expected));
	/* Even a metadata change has a different canonical commitment. */
	batch.policy_epoch++;
	zassert_ok(pqcp_sovereign_audit_cbor_encode_batch_body(
		&batch, ref_buf, sizeof(ref_buf), &body_length));
	zassert_equal(psa_hash_setup(&hash, PSA_ALG_SHA_256), PSA_SUCCESS);
	zassert_equal(psa_hash_update(&hash, domain, sizeof(domain) - 1U), PSA_SUCCESS);
	zassert_equal(psa_hash_update(&hash, ref_buf, body_length), PSA_SUCCESS);
	zassert_equal(psa_hash_finish(&hash, expected, sizeof(expected), &hash_length), PSA_SUCCESS);
	zassert_not_equal(memcmp(expected, batch.batch_digest, sizeof(expected)), 0);
}

static uint8_t checkpoint_scratch[OUT_CAPACITY];
static uint8_t checkpoint_slots[2][OUT_CAPACITY];
static size_t checkpoint_lengths[2];
static bool tear_checkpoint;

static int read_checkpoint(void *context, unsigned int slot, uint8_t *buffer,
	size_t capacity, size_t *length)
{
	ARG_UNUSED(context);
	*length = checkpoint_lengths[slot];
	if (*length == 0U) {
		return -ENOENT;
	}
	if (*length > capacity) {
		return -ENOSPC;
	}
	memcpy(buffer, checkpoint_slots[slot], *length);
	return 0;
}

static int write_checkpoint(void *context, unsigned int slot, const uint8_t *buffer,
	size_t length)
{
	ARG_UNUSED(context);
	zassert_true(length <= sizeof(checkpoint_slots[slot]));
	checkpoint_lengths[slot] = tear_checkpoint ? length / 2U : length;
	memcpy(checkpoint_slots[slot], buffer, checkpoint_lengths[slot]);
	return tear_checkpoint ? -EIO : 0;
}

static const struct pqcp_sovereign_audit_checkpoint_store checkpoint_store = {
	.read = read_checkpoint,
	.write = write_checkpoint,
	.binding = { 0xA5U },
};

static int recover_exporter(uint64_t minimum_generation)
{
	zassert_ok(pqcp_sovereign_audit_exporter_init(
		&exporter, &ledger, &export_config, &export_storage));
	return pqcp_sovereign_audit_exporter_recover(&exporter, &checkpoint_store,
		minimum_generation, checkpoint_scratch, sizeof(checkpoint_scratch));
}

static int save_exporter(void)
{
	return pqcp_sovereign_audit_exporter_checkpoint(
		&exporter, checkpoint_scratch, sizeof(checkpoint_scratch));
}

ZTEST(pqcp_sovereign_audit, test_export_checkpoint_torn_slot_and_ack_restart)
{
	uint8_t digest[DIGEST_BYTES];
	uint64_t id;
	size_t length;

	append_events(0U, 3U, NULL);
	reset_exporter();
	memset(checkpoint_lengths, 0, sizeof(checkpoint_lengths));
	tear_checkpoint = false;
	zassert_equal(recover_exporter(0U), -ENOENT);
	id = open_export();
	zassert_ok(prepare_export(id, 2001U));
	length = batch.encoded_length;
	memcpy(ref_buf, out_buf, length);
	memcpy(digest, batch.batch_digest, sizeof(digest));
	zassert_ok(save_exporter());
	zassert_ok(pqcp_sovereign_audit_export_acknowledge(
		&exporter, id, 1U, 2U, digest, 2002U));
	tear_checkpoint = true;
	zassert_equal(save_exporter(), -EIO);
	tear_checkpoint = false;

	zassert_equal(recover_exporter(2U), -ESTALE);
	zassert_ok(recover_exporter(1U));
	zassert_ok(prepare_export(id, 2003U));
	zassert_true(batch.resumed);
	zassert_equal(batch.encoded_length, length);
	zassert_mem_equal(out_buf, ref_buf, length);
	zassert_ok(pqcp_sovereign_audit_export_acknowledge(
		&exporter, id, 1U, 2U, digest, 2004U));
	zassert_ok(save_exporter());
	zassert_ok(recover_exporter(2U));
	zassert_ok(prepare_export(id, 2005U));
	zassert_equal(batch.first_sequence, 3U);
	zassert_mem_equal(batch.previous_batch_digest, digest, sizeof(digest));
	zassert_equal(pqcp_sovereign_audit_exporter_recover(&exporter, &checkpoint_store,
		0U, checkpoint_scratch, sizeof(checkpoint_scratch)), -EBUSY);
	zassert_ok(pqcp_sovereign_audit_export_close(&exporter, id));
	zassert_ok(save_exporter());
	zassert_ok(recover_exporter(3U));
	zassert_equal(prepare_export(id, 2006U), -ENOENT);
	zassert_true(open_export() > id);
	reset_ledger(8U, 1U);
	zassert_equal(recover_exporter(3U), -ESTALE);
	append_events(10U, 3U, NULL);
	zassert_equal(recover_exporter(3U), -ESTALE);
}

ZTEST(pqcp_sovereign_audit, test_export_real_mldsa_signature_and_failure_atomicity)
{
	static struct pqcp_runtime_key_store store;
	static struct pqcp_runtime_volatile_context context;
	static struct pqcp_runtime_volatile_slot slots[1];
	const struct pqcp_runtime_key_request request = {
		.family = PQCP_RUNTIME_KEY_MLDSA_KEYPAIR,
		.level = 65U,
		.usage = PQCP_RUNTIME_USAGE_SIGN | PQCP_RUNTIME_USAGE_VERIFY | PQCP_RUNTIME_USAGE_DESTROY,
		.now_ms = 1000U,
		.owner = "audit-test", .label = "audit-signing",
	};

	append_events(0U, 1U, NULL);
	reset_exporter();
	zassert_ok(pqcp_runtime_volatile_store_init(&store, &context, slots, ARRAY_SIZE(slots)));
	export_config.key_store = &store;
	export_config.signing_enabled = true;
	export_config.signature_required = true;
	zassert_ok(pqcp_runtime_key_store_generate(&store, &request, &export_config.signing_key));
	memset(checkpoint_lengths, 0, sizeof(checkpoint_lengths));
	tear_checkpoint = false;
	zassert_equal(recover_exporter(0U), -ENOENT);
	uint64_t id = open_export();

	zassert_ok(prepare_export(id, 2001U));
	zassert_equal(batch.signature_algorithm, PQCP_SOVEREIGN_AUDIT_SIGNATURE_MLDSA);
	zassert_true(batch.signature_length > 0U);
	zassert_ok(pqcp_runtime_key_store_verify(&store, &export_config.signing_key,
		batch.batch_digest, DIGEST_BYTES, (const uint8_t *)PQCP_SOVEREIGN_AUDIT_SIGNATURE_CONTEXT,
		sizeof(PQCP_SOVEREIGN_AUDIT_SIGNATURE_CONTEXT) - 1U, batch.signature, batch.signature_length));
	size_t length = batch.encoded_length;

	memcpy(ref_buf, out_buf, length);
	zassert_true(pqcp_sovereign_audit_exporter_checkpoint_capacity(&exporter) <=
		     sizeof(checkpoint_scratch));
	zassert_ok(save_exporter());
	/* New exporter RAM and a new live event buffer. The signed projected
	 * batch survives even when the original event is no longer retained.
	 */
	static struct pqcp_sovereign_event restarted_events[2];
	struct pqcp_sovereign_audit_export_storage restarted_storage = export_storage;

	restarted_storage.workspace_events = restarted_events;
	append_events(10U, 10U, NULL);
	zassert_ok(pqcp_sovereign_audit_exporter_init(
		&exporter, &ledger, &export_config, &restarted_storage));
	zassert_ok(pqcp_sovereign_audit_exporter_recover(&exporter, &checkpoint_store,
		1U, checkpoint_scratch, sizeof(checkpoint_scratch)));
	zassert_ok(prepare_export(id, 2002U));
	zassert_equal_ptr(batch.events, restarted_events);
	zassert_mem_equal(out_buf, ref_buf, length);
	batch.batch_digest[0] ^= 1U;
	zassert_not_equal(pqcp_runtime_key_store_verify(&store, &export_config.signing_key,
		batch.batch_digest, DIGEST_BYTES, (const uint8_t *)PQCP_SOVEREIGN_AUDIT_SIGNATURE_CONTEXT,
		sizeof(PQCP_SOVEREIGN_AUDIT_SIGNATURE_CONTEXT) - 1U, batch.signature, batch.signature_length), 0);
	zassert_ok(pqcp_sovereign_audit_export_close(&exporter, id));
	zassert_ok(pqcp_runtime_key_store_destroy(&store, &export_config.signing_key));
	id = open_export();
	zassert_not_equal(prepare_export(id, 2003U), 0);
	zassert_equal(export_cursors[0].state, PQCP_SOVEREIGN_AUDIT_CURSOR_ACTIVE);
	zassert_equal(exporter.pending_batch.cursor_id, 0U);
}

/* ------------------------------------------------------------------ */
/* Enum stringification                                                */
/* ------------------------------------------------------------------ */

ZTEST(pqcp_sovereign_audit, test_enum_strings)
{
	static const char *const classes[] = {
		"none", "crypto_operation", "fleet_operation",
		"security_incident", "deployment", "key_ceremony", "privacy",
		"recovery", "continuity", "audit_control",
	};
	static const char *const activities[] = {
		"none", "create", "start", "update", "authorize", "approve",
		"reject", "execute", "complete", "cancel", "expire", "revoke",
		"rotate", "destroy", "deploy", "rollback", "quarantine",
		"contain", "remediate", "recover", "failover", "rejoin",
		"read", "write", "export", "erase", "acknowledge",
	};
	static const char *const severities[] = {
		"unknown", "informational", "low", "medium", "high", "critical",
	};
	static const char *const outcomes[] = {
		"unknown", "success", "failure", "denied", "pending",
		"cancelled", "expired",
	};

	zassert_equal(ARRAY_SIZE(classes),
		      (size_t)PQCP_SOVEREIGN_AUDIT_CLASS_COUNT);
	zassert_equal(ARRAY_SIZE(activities),
		      (size_t)PQCP_SOVEREIGN_AUDIT_ACTIVITY_COUNT);
	for (size_t index = 0U; index < ARRAY_SIZE(classes); ++index) {
		zassert_str_equal(pqcp_sovereign_audit_event_class_str(
					  (enum pqcp_sovereign_audit_event_class)index),
				  classes[index]);
	}
	for (size_t index = 0U; index < ARRAY_SIZE(activities); ++index) {
		zassert_str_equal(pqcp_sovereign_audit_activity_str(
					  (enum pqcp_sovereign_audit_activity)index),
				  activities[index]);
	}
	for (size_t index = 0U; index < ARRAY_SIZE(severities); ++index) {
		zassert_str_equal(pqcp_sovereign_audit_severity_str(
					  (enum pqcp_sovereign_audit_severity)index),
				  severities[index]);
	}
	for (size_t index = 0U; index < ARRAY_SIZE(outcomes); ++index) {
		zassert_str_equal(pqcp_sovereign_audit_outcome_str(
					  (enum pqcp_sovereign_audit_outcome)index),
				  outcomes[index]);
	}
	/* Out-of-range values map to the neutral strings, never NULL. */
	zassert_str_equal(pqcp_sovereign_audit_event_class_str(
				  PQCP_SOVEREIGN_AUDIT_CLASS_COUNT), "none");
	zassert_str_equal(pqcp_sovereign_audit_event_class_str(
				  (enum pqcp_sovereign_audit_event_class)99),
			  "none");
	zassert_str_equal(pqcp_sovereign_audit_activity_str(
				  PQCP_SOVEREIGN_AUDIT_ACTIVITY_COUNT), "none");
	zassert_str_equal(pqcp_sovereign_audit_severity_str(
				  (enum pqcp_sovereign_audit_severity)99),
			  "unknown");
	zassert_str_equal(pqcp_sovereign_audit_outcome_str(
				  (enum pqcp_sovereign_audit_outcome)99),
			  "unknown");
}

/* ------------------------------------------------------------------ */
/* Event construction                                                  */
/* ------------------------------------------------------------------ */

ZTEST(pqcp_sovereign_audit, test_event_init_populates_and_derives_id)
{
	struct pqcp_sovereign_event_draft draft;
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event again;
	struct pqcp_sovereign_event other;
	uint8_t zero_id[PQCP_SOVEREIGN_AUDIT_EVENT_ID_BYTES] = { 0 };

	fill_draft(&draft, 0U);
	zassert_ok(pqcp_sovereign_event_init(&event, &draft));
	zassert_equal(event.schema_version,
		      PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION);
	zassert_equal(event.generation, 1U);
	zassert_equal(event.sequence, 0U, "sequence is ledger-assigned");
	zassert_false(event.occupied, "uncommitted event is not occupied");
	zassert_equal(event.observed_at_ms, 1000U);
	zassert_equal(event.ingested_at_ms, 1005U);
	zassert_equal(event.correlation_id, 4242U);
	zassert_equal(event.policy_epoch, 7U);
	zassert_equal(event.revocation_epoch, 3U);
	zassert_equal(event.tenant.policy_epoch, 7U);
	zassert_equal(event.tenant.revocation_epoch, 3U);
	zassert_equal(event.event_class, PQCP_SOVEREIGN_AUDIT_CLASS_DEPLOYMENT);
	zassert_equal(event.activity, PQCP_SOVEREIGN_AUDIT_ACTIVITY_DEPLOY);
	zassert_equal(event.severity, PQCP_SOVEREIGN_AUDIT_SEVERITY_HIGH);
	zassert_equal(event.outcome, PQCP_SOVEREIGN_AUDIT_OUTCOME_SUCCESS);
	zassert_equal(event.attribute_count, 0U);
	zassert_str_equal(event.tenant.tenant_id, "tenant-a");
	zassert_str_equal(event.tenant.realm, "eu");
	zassert_str_equal(event.source, "unit");
	zassert_str_equal(event.actor, "alice");
	zassert_str_equal(event.object, "key/1");
	zassert_str_equal(event.action, "sign");
	zassert_str_equal(event.reason, "because");
	zassert_mem_equal(event.actor_digest, d_actor, DIGEST_BYTES);
	zassert_mem_equal(event.receipt_digest, d_receipt, DIGEST_BYTES);
	zassert_not_equal(memcmp(event.event_id, zero_id, sizeof(zero_id)), 0,
			  "event id must be derived");
	zassert_false(pqcp_sovereign_event_verify(&event) == 0,
		      "an uncommitted event must not verify");

	/* The id is a deterministic function of the draft. */
	zassert_ok(pqcp_sovereign_event_init(&again, &draft));
	zassert_mem_equal(event.event_id, again.event_id,
			  sizeof(event.event_id));
	zassert_mem_equal(event.tenant.scope_digest, again.tenant.scope_digest,
			  DIGEST_BYTES);

	/* ...and distinct drafts yield distinct ids. */
	fill_draft(&draft, 1U);
	zassert_ok(pqcp_sovereign_event_init(&other, &draft));
	zassert_not_equal(memcmp(event.event_id, other.event_id,
				 sizeof(event.event_id)), 0);
	fill_draft(&draft, 0U);
	draft.action = "verify";
	zassert_ok(pqcp_sovereign_event_init(&other, &draft));
	zassert_not_equal(memcmp(event.event_id, other.event_id,
				 sizeof(event.event_id)), 0);
	fill_draft(&draft, 0U);
	draft.tenant_id = "tenant-b";
	zassert_ok(pqcp_sovereign_event_init(&other, &draft));
	zassert_not_equal(memcmp(event.event_id, other.event_id,
				 sizeof(event.event_id)), 0);
	zassert_not_equal(memcmp(event.tenant.scope_digest,
				 other.tenant.scope_digest, DIGEST_BYTES), 0,
			  "scope digest binds the tenant");

	/* Optional text and digests default to empty / zero. */
	fill_draft(&draft, 0U);
	draft.realm = NULL;
	draft.actor = NULL;
	draft.object = NULL;
	draft.action = NULL;
	draft.reason = NULL;
	draft.actor_digest = NULL;
	draft.subject_digest = NULL;
	draft.resource_digest = NULL;
	draft.evidence_digest = NULL;
	draft.receipt_digest = NULL;
	zassert_ok(pqcp_sovereign_event_init(&other, &draft));
	zassert_equal(other.tenant.realm[0], '\0');
	zassert_equal(other.actor[0], '\0');
	zassert_equal(other.object[0], '\0');
	zassert_equal(other.action[0], '\0');
	zassert_equal(other.reason[0], '\0');
	for (size_t index = 0U; index < DIGEST_BYTES; ++index) {
		zassert_equal(other.actor_digest[index], 0U);
		zassert_equal(other.receipt_digest[index], 0U);
	}

	/* A bounded expiry in the future of observation is accepted. */
	fill_draft(&draft, 0U);
	draft.expires_at_ms = draft.observed_at_ms + 1U;
	zassert_ok(pqcp_sovereign_event_init(&other, &draft));
	zassert_equal(other.expires_at_ms, 1001U);
}

#define EXPECT_INIT_REJECTED(mutation)                                         \
	do {                                                                   \
		fill_draft(&draft, 0U);                                        \
		mutation;                                                      \
		zassert_equal(pqcp_sovereign_event_init(&event, &draft),       \
			      -EINVAL, "not rejected: " #mutation);            \
	} while (0)

ZTEST(pqcp_sovereign_audit, test_event_init_rejects_invalid_drafts)
{
	struct pqcp_sovereign_event_draft draft;
	struct pqcp_sovereign_event event;
	char text[256];

	fill_draft(&draft, 0U);
	zassert_equal(pqcp_sovereign_event_init(NULL, &draft), -EINVAL);
	zassert_equal(pqcp_sovereign_event_init(&event, NULL), -EINVAL);

	EXPECT_INIT_REJECTED(draft.event_class = PQCP_SOVEREIGN_AUDIT_CLASS_NONE);
	EXPECT_INIT_REJECTED(draft.event_class = PQCP_SOVEREIGN_AUDIT_CLASS_COUNT);
	EXPECT_INIT_REJECTED(draft.activity = PQCP_SOVEREIGN_AUDIT_ACTIVITY_NONE);
	EXPECT_INIT_REJECTED(draft.activity = PQCP_SOVEREIGN_AUDIT_ACTIVITY_COUNT);
	EXPECT_INIT_REJECTED(draft.severity =
				     (enum pqcp_sovereign_audit_severity)6);
	EXPECT_INIT_REJECTED(draft.outcome =
				     (enum pqcp_sovereign_audit_outcome)7);
	EXPECT_INIT_REJECTED(draft.data_class =
				     PQCP_SOVEREIGN_AUDIT_DATA_CLASS_COUNT);
	EXPECT_INIT_REJECTED(draft.observed_at_ms = 0U);
	EXPECT_INIT_REJECTED(draft.ingested_at_ms = draft.observed_at_ms - 1U);
	EXPECT_INIT_REJECTED(draft.expires_at_ms = draft.observed_at_ms);
	EXPECT_INIT_REJECTED(draft.expires_at_ms = draft.observed_at_ms - 1U);
	EXPECT_INIT_REJECTED(draft.flags = (1U << 8));
	EXPECT_INIT_REJECTED(draft.flags = 0x80000000U);
	EXPECT_INIT_REJECTED(draft.tenant_id = NULL);
	EXPECT_INIT_REJECTED(draft.tenant_id = "");
	EXPECT_INIT_REJECTED(draft.source = NULL);
	EXPECT_INIT_REJECTED(draft.source = "");
	/* Control characters and non-ASCII bytes are never admitted. */
	EXPECT_INIT_REJECTED(draft.actor = "line\nbreak");
	EXPECT_INIT_REJECTED(draft.object = "tab\there");
	EXPECT_INIT_REJECTED(draft.reason = "del\x7f");
	EXPECT_INIT_REJECTED(draft.action = "caf\xc3\xa9");
	EXPECT_INIT_REJECTED(draft.realm = "bad\r");

	/* Text bounds: max-1 characters fit, max characters do not. */
	struct {
		const char **field_ref;
		size_t capacity;
	} bounds[] = {
		{ &draft.tenant_id, PQCP_SOVEREIGN_AUDIT_TENANT_MAX_CHARS },
		{ &draft.realm, PQCP_SOVEREIGN_AUDIT_REALM_MAX_CHARS },
		{ &draft.source, PQCP_SOVEREIGN_AUDIT_SOURCE_MAX_CHARS },
		{ &draft.actor, PQCP_SOVEREIGN_AUDIT_ACTOR_MAX_CHARS },
		{ &draft.object, PQCP_SOVEREIGN_AUDIT_OBJECT_MAX_CHARS },
		{ &draft.action, PQCP_SOVEREIGN_AUDIT_ACTION_MAX_CHARS },
		{ &draft.reason, PQCP_SOVEREIGN_AUDIT_REASON_MAX_CHARS },
	};

	for (size_t index = 0U; index < ARRAY_SIZE(bounds); ++index) {
		fill_draft(&draft, 0U);
		make_str(text, bounds[index].capacity - 1U);
		*bounds[index].field_ref = text;
		zassert_ok(pqcp_sovereign_event_init(&event, &draft),
			   "max-length field %zu rejected", index);
		make_str(text, bounds[index].capacity);
		zassert_equal(pqcp_sovereign_event_init(&event, &draft),
			      -EINVAL, "overlong field %zu accepted", index);
	}
}

ZTEST(pqcp_sovereign_audit, test_event_id_helpers)
{
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event committed;
	uint8_t custom[PQCP_SOVEREIGN_AUDIT_EVENT_ID_BYTES];
	uint8_t zero_id[PQCP_SOVEREIGN_AUDIT_EVENT_ID_BYTES] = { 0 };
	uint8_t original[PQCP_SOVEREIGN_AUDIT_EVENT_ID_BYTES];

	make_event(&event, 0U);
	memcpy(original, event.event_id, sizeof(original));
	memset(custom, 0x5c, sizeof(custom));

	zassert_equal(pqcp_sovereign_event_set_id(NULL, custom), -EINVAL);
	zassert_equal(pqcp_sovereign_event_set_id(&event, NULL), -EINVAL);
	zassert_equal(pqcp_sovereign_event_set_id(&event, zero_id), -EINVAL,
		      "all-zero id is reserved");
	zassert_mem_equal(event.event_id, original, sizeof(original),
			  "rejected set_id must not change the id");

	zassert_ok(pqcp_sovereign_event_set_id(&event, custom));
	zassert_mem_equal(event.event_id, custom, sizeof(custom));

	/* derive_id restores the canonical id. */
	zassert_ok(pqcp_sovereign_event_derive_id(&event));
	zassert_mem_equal(event.event_id, original, sizeof(original));

	/* The ledger preserves a caller-supplied id. */
	zassert_ok(pqcp_sovereign_event_set_id(&event, custom));
	zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
						      &committed));
	zassert_mem_equal(committed.event_id, custom, sizeof(custom));

	/* derive_id argument and state validation. */
	zassert_equal(pqcp_sovereign_event_derive_id(NULL), -EINVAL);
	make_event(&event, 0U);
	event.schema_version = 0U;
	zassert_equal(pqcp_sovereign_event_derive_id(&event), -EINVAL);
	make_event(&event, 0U);
	event.observed_at_ms = 0U;
	zassert_equal(pqcp_sovereign_event_derive_id(&event), -EINVAL);
	make_event(&event, 0U);
	event.event_class = PQCP_SOVEREIGN_AUDIT_CLASS_NONE;
	zassert_equal(pqcp_sovereign_event_derive_id(&event), -EINVAL);
	make_event(&event, 0U);
	event.activity = PQCP_SOVEREIGN_AUDIT_ACTIVITY_COUNT;
	zassert_equal(pqcp_sovereign_event_derive_id(&event), -EINVAL);
}

/* ------------------------------------------------------------------ */
/* Attributes                                                          */
/* ------------------------------------------------------------------ */

ZTEST(pqcp_sovereign_audit, test_event_attributes_sorted_and_typed)
{
	struct pqcp_sovereign_event event;
	uint8_t digest[DIGEST_BYTES];

	make_event(&event, 0U);
	fill_digest(digest, 0x77U);

	/* Insert out of order; storage must be sorted by key. */
	zassert_ok(pqcp_sovereign_event_add_text(&event, "m_text", "hello", 0U));
	zassert_ok(pqcp_sovereign_event_add_u64(&event, "z_u64", UINT64_MAX,
						PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_REGULATORY));
	zassert_ok(pqcp_sovereign_event_add_i64(&event, "a_i64", INT64_MIN,
						PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_PERSONAL));
	zassert_ok(pqcp_sovereign_event_add_bool(&event, "q_bool", true,
						 PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_SENSITIVE));
	zassert_ok(pqcp_sovereign_event_add_digest(&event, "b.digest-1", digest,
						   0U));
	zassert_equal(event.attribute_count, 5U);
	for (size_t index = 1U; index < event.attribute_count; ++index) {
		zassert_true(strcmp(event.attributes[index - 1U].key,
				    event.attributes[index].key) < 0,
			     "attributes not strictly sorted");
	}
	zassert_str_equal(event.attributes[0].key, "a_i64");
	zassert_equal(event.attributes[0].type,
		      PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_I64);
	zassert_equal(event.attributes[0].value.i64, INT64_MIN);
	zassert_equal(event.attributes[0].flags,
		      PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_PERSONAL);
	zassert_str_equal(event.attributes[1].key, "b.digest-1");
	zassert_equal(event.attributes[1].type,
		      PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_DIGEST);
	zassert_mem_equal(event.attributes[1].value.digest, digest,
			  DIGEST_BYTES);
	zassert_str_equal(event.attributes[2].key, "m_text");
	zassert_str_equal(event.attributes[2].value.text, "hello");
	zassert_str_equal(event.attributes[3].key, "q_bool");
	zassert_true(event.attributes[3].value.boolean);
	zassert_str_equal(event.attributes[4].key, "z_u64");
	zassert_equal(event.attributes[4].value.u64, UINT64_MAX);

	/* Empty text value is legal. */
	zassert_ok(pqcp_sovereign_event_add_text(&event, "empty", "", 0U));
	zassert_equal(event.attribute_count, 6U);

	/* Attributes participate in the digest once committed. */
	{
		struct pqcp_sovereign_event plain;
		struct pqcp_sovereign_event with_attr;
		struct pqcp_sovereign_event c1;
		struct pqcp_sovereign_event c2;

		make_event(&plain, 0U);
		make_event(&with_attr, 0U);
		zassert_ok(pqcp_sovereign_event_add_u64(&with_attr, "k", 1U, 0U));
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &plain,
							      &c1));
		reset_ledger(8U, 1U);
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &with_attr,
							      &c2));
		zassert_not_equal(memcmp(c1.event_digest, c2.event_digest,
					 DIGEST_BYTES), 0);
	}
}

ZTEST(pqcp_sovereign_audit, test_event_attribute_negative_paths)
{
	struct pqcp_sovereign_event event;
	char text[160];
	uint8_t digest[DIGEST_BYTES];
	char key[64];

	make_event(&event, 0U);
	fill_digest(digest, 0x01U);

	/* NULL event / key / value */
	zassert_equal(pqcp_sovereign_event_add_u64(NULL, "k", 1U, 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_i64(NULL, "k", 1, 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_bool(NULL, "k", true, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_text(NULL, "k", "v", 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_digest(NULL, "k", digest, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_u64(&event, NULL, 1U, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_i64(&event, NULL, 1, 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_bool(&event, NULL, true, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_text(&event, NULL, "v", 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_text(&event, "k", NULL, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_digest(&event, "k", NULL, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_digest(&event, NULL, digest, 0U),
		      -EINVAL);
	zassert_equal(event.attribute_count, 0U, "failed adds must not insert");

	/* Key syntax: [A-Za-z0-9_.-]{1,39} */
	zassert_equal(pqcp_sovereign_event_add_u64(&event, "", 1U, 0U), -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_u64(&event, "has space", 1U, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_u64(&event, "eq=sign", 1U, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_u64(&event, "pipe|", 1U, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_u64(&event, "new\nline", 1U, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_u64(&event, "quote\"", 1U, 0U),
		      -EINVAL);
	make_str(key, PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_KEY_MAX_CHARS - 1U);
	zassert_ok(pqcp_sovereign_event_add_u64(&event, key, 1U, 0U));
	make_str(key, PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_KEY_MAX_CHARS);
	zassert_equal(pqcp_sovereign_event_add_u64(&event, key, 1U, 0U),
		      -EINVAL);

	/* Unknown attribute flags */
	zassert_equal(pqcp_sovereign_event_add_u64(&event, "flags", 1U, 0x8U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_bool(&event, "flags", true,
						    0x80000000U), -EINVAL);

	/* Text value bounds and charset */
	make_str(text, PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT_MAX_CHARS - 1U);
	zassert_ok(pqcp_sovereign_event_add_text(&event, "t_max", text, 0U));
	make_str(text, PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT_MAX_CHARS);
	zassert_equal(pqcp_sovereign_event_add_text(&event, "t_over", text, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_text(&event, "t_ctl", "a\nb", 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_text(&event, "t_hi", "\xff", 0U),
		      -EINVAL);

	/* Duplicate keys are refused for every type, original preserved. */
	zassert_ok(pqcp_sovereign_event_add_u64(&event, "dup", 5U, 0U));
	zassert_equal(pqcp_sovereign_event_add_u64(&event, "dup", 6U, 0U),
		      -EEXIST);
	zassert_equal(pqcp_sovereign_event_add_text(&event, "dup", "x", 0U),
		      -EEXIST);
	for (size_t index = 0U; index < event.attribute_count; ++index) {
		if (strcmp(event.attributes[index].key, "dup") == 0) {
			zassert_equal(event.attributes[index].value.u64, 5U);
		}
	}

	/* Capacity: exactly MAX attributes, then the next is refused. */
	make_event(&event, 0U);
	for (size_t index = 0U; index < PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES;
	     ++index) {
		snprintf(key, sizeof(key), "k%02u", (unsigned int)index);
		zassert_ok(pqcp_sovereign_event_add_u64(&event, key, index, 0U));
	}
	zassert_equal(event.attribute_count,
		      PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES);
	zassert_equal(pqcp_sovereign_event_add_u64(&event, "overflow", 1U, 0U),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_add_text(&event, "overflow", "x", 0U),
		      -EINVAL);
	zassert_equal(event.attribute_count,
		      PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES);

	/* A full event is still committable and verifiable. */
	{
		struct pqcp_sovereign_event committed;

		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
							      &committed));
		zassert_ok(pqcp_sovereign_event_verify(&committed));
	}
}

/* ------------------------------------------------------------------ */
/* Event digest / verify                                               */
/* ------------------------------------------------------------------ */

#define EXPECT_TAMPER_DETECTED(mutation)                                       \
	do {                                                                   \
		tampered = committed;                                          \
		mutation;                                                      \
		zassert_not_equal(pqcp_sovereign_event_verify(&tampered), 0,   \
				  "tamper not detected: " #mutation);          \
	} while (0)

ZTEST(pqcp_sovereign_audit, test_event_digest_and_verify_contracts)
{
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event committed;
	struct pqcp_sovereign_event tampered;
	uint8_t digest[DIGEST_BYTES];
	uint8_t other[DIGEST_BYTES];

	make_event(&event, 0U);
	add_rich_attributes(&event);
	zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
						      &committed));
	zassert_true(committed.occupied);
	zassert_equal(committed.sequence, 1U);
	zassert_ok(pqcp_sovereign_event_verify(&committed));

	/* The stored digest is the canonical digest. */
	zassert_ok(pqcp_sovereign_event_digest(&committed, digest));
	zassert_mem_equal(digest, committed.event_digest, DIGEST_BYTES);

	/* Argument validation. */
	zassert_equal(pqcp_sovereign_event_digest(NULL, digest), -EINVAL);
	zassert_equal(pqcp_sovereign_event_digest(&committed, NULL), -EINVAL);
	zassert_equal(pqcp_sovereign_event_verify(NULL), -EINVAL);
	/* An uncommitted event has no sequence: no digest, no verification. */
	zassert_equal(pqcp_sovereign_event_digest(&event, digest), -EINVAL);
	zassert_equal(pqcp_sovereign_event_verify(&event), -EINVAL);

	/* Every semantically relevant field is bound by the digest. */
	EXPECT_TAMPER_DETECTED(tampered.reason[0] ^= 0x01);
	EXPECT_TAMPER_DETECTED(tampered.source[0] = 'U');
	EXPECT_TAMPER_DETECTED(tampered.actor[0] = 'A');
	EXPECT_TAMPER_DETECTED(tampered.object[0] = 'K');
	EXPECT_TAMPER_DETECTED(tampered.action[0] = 'S');
	EXPECT_TAMPER_DETECTED(tampered.tenant.tenant_id[0] = 'T');
	EXPECT_TAMPER_DETECTED(tampered.tenant.realm[0] = 'E');
	EXPECT_TAMPER_DETECTED(tampered.severity =
				       PQCP_SOVEREIGN_AUDIT_SEVERITY_LOW);
	EXPECT_TAMPER_DETECTED(tampered.outcome =
				       PQCP_SOVEREIGN_AUDIT_OUTCOME_FAILURE);
	EXPECT_TAMPER_DETECTED(tampered.data_class =
				       PQCP_SOVEREIGN_AUDIT_DATA_PUBLIC);
	EXPECT_TAMPER_DETECTED(tampered.event_class =
				       PQCP_SOVEREIGN_AUDIT_CLASS_PRIVACY);
	EXPECT_TAMPER_DETECTED(tampered.activity =
				       PQCP_SOVEREIGN_AUDIT_ACTIVITY_ROLLBACK);
	EXPECT_TAMPER_DETECTED(tampered.flags ^=
			       PQCP_SOVEREIGN_AUDIT_EVENT_OPERATOR_VISIBLE);
	EXPECT_TAMPER_DETECTED(tampered.result = -1);
	EXPECT_TAMPER_DETECTED(tampered.correlation_id++);
	EXPECT_TAMPER_DETECTED(tampered.observed_at_ms++);
	EXPECT_TAMPER_DETECTED(tampered.ingested_at_ms++);
	EXPECT_TAMPER_DETECTED(tampered.expires_at_ms = 99999U);
	EXPECT_TAMPER_DETECTED(tampered.sequence++);
	EXPECT_TAMPER_DETECTED(tampered.generation++);
	EXPECT_TAMPER_DETECTED(tampered.event_id[3] ^= 0x80);
	EXPECT_TAMPER_DETECTED(tampered.actor_digest[0] ^= 1U);
	EXPECT_TAMPER_DETECTED(tampered.subject_digest[31] ^= 1U);
	EXPECT_TAMPER_DETECTED(tampered.resource_digest[5] ^= 1U);
	EXPECT_TAMPER_DETECTED(tampered.evidence_digest[5] ^= 1U);
	EXPECT_TAMPER_DETECTED(tampered.receipt_digest[5] ^= 1U);
	EXPECT_TAMPER_DETECTED(tampered.previous_digest[5] ^= 1U);
	EXPECT_TAMPER_DETECTED(tampered.event_digest[5] ^= 1U);
	EXPECT_TAMPER_DETECTED(tampered.attributes[0].value.u64++);
	EXPECT_TAMPER_DETECTED(tampered.attributes[1].value.i64 = 0);
	EXPECT_TAMPER_DETECTED(tampered.attributes[2].value.boolean = false);
	EXPECT_TAMPER_DETECTED(tampered.attributes[3].value.text[0] = 'X');
	EXPECT_TAMPER_DETECTED(tampered.attributes[4].value.digest[0] ^= 1U);
	EXPECT_TAMPER_DETECTED(tampered.attributes[0].flags ^=
			       PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_SENSITIVE);
	EXPECT_TAMPER_DETECTED(tampered.attribute_count--);
	EXPECT_TAMPER_DETECTED(tampered.tenant.scope_digest[0] ^= 1U);
	EXPECT_TAMPER_DETECTED(tampered.tenant.policy_epoch++);
	EXPECT_TAMPER_DETECTED(tampered.policy_epoch++);

	/* Structural invariants are rejected with -EINVAL / -EBADMSG. */
	tampered = committed;
	tampered.schema_version = 2U;
	zassert_equal(pqcp_sovereign_event_verify(&tampered), -EINVAL);
	tampered = committed;
	tampered.occupied = false;
	zassert_equal(pqcp_sovereign_event_verify(&tampered), -EINVAL);
	tampered = committed;
	tampered.attribute_count = PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES + 1U;
	zassert_equal(pqcp_sovereign_event_verify(&tampered), -EINVAL);
	tampered = committed;
	tampered.flags |= (1U << 20);
	zassert_equal(pqcp_sovereign_event_verify(&tampered), -EINVAL);
	tampered = committed;
	memset(tampered.event_digest, 0, DIGEST_BYTES);
	zassert_equal(pqcp_sovereign_event_verify(&tampered), -EINVAL);
	tampered = committed;
	tampered.reason[0] = '\n';
	zassert_equal(pqcp_sovereign_event_verify(&tampered), -EINVAL,
		      "control characters in text are structurally invalid");
	tampered = committed;
	tampered.sequence = 0U;
	zassert_equal(pqcp_sovereign_event_verify(&tampered), -EINVAL);

	/* Unsorted or duplicate attribute keys are rejected even if re-hashed. */
	tampered = committed;
	{
		struct pqcp_sovereign_audit_attribute swap =
			tampered.attributes[0];

		tampered.attributes[0] = tampered.attributes[1];
		tampered.attributes[1] = swap;
	}
	zassert_ok(pqcp_sovereign_event_digest(&tampered, other));
	memcpy(tampered.event_digest, other, DIGEST_BYTES);
	zassert_equal(pqcp_sovereign_event_verify(&tampered), -EBADMSG);
	tampered = committed;
	tampered.attributes[1] = tampered.attributes[0];
	zassert_ok(pqcp_sovereign_event_digest(&tampered, other));
	memcpy(tampered.event_digest, other, DIGEST_BYTES);
	zassert_equal(pqcp_sovereign_event_verify(&tampered), -EBADMSG);

	/* Digest is sensitive to sequence. */
	tampered = committed;
	tampered.sequence = 2U;
	zassert_ok(pqcp_sovereign_event_digest(&tampered, other));
	zassert_not_equal(memcmp(other, digest, DIGEST_BYTES), 0);
}

/* ------------------------------------------------------------------ */
/* Redaction                                                           */
/* ------------------------------------------------------------------ */

static bool is_pseudonym(const char *text)
{
	if (strlen(text) != 18U || text[0] != 'h' || text[1] != ':') {
		return false;
	}
	for (size_t index = 2U; index < 18U; ++index) {
		bool digit = text[index] >= '0' && text[index] <= '9';
		bool lower = text[index] >= 'a' && text[index] <= 'f';

		if (!digit && !lower) {
			return false;
		}
	}
	return true;
}

static void make_privacy_event(struct pqcp_sovereign_event *committed,
			       const char *tenant)
{
	struct pqcp_sovereign_event_draft draft;
	struct pqcp_sovereign_event event;

	fill_draft(&draft, 0U);
	draft.tenant_id = tenant;
	zassert_ok(pqcp_sovereign_event_init(&event, &draft));
	zassert_ok(pqcp_sovereign_event_add_text(
		&event, "p_email", "bob@example.com",
		PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_PERSONAL));
	zassert_ok(pqcp_sovereign_event_add_text(&event, "q_note", "public-note",
						 0U));
	zassert_ok(pqcp_sovereign_event_add_text(
		&event, "r_secret", "s3cr3t-value",
		PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_SENSITIVE));
	zassert_ok(pqcp_sovereign_event_add_u64(&event, "s_count", 9U, 0U));
	reset_ledger(8U, 1U);
	zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
						      committed));
}

static const struct pqcp_sovereign_audit_attribute *
find_attribute(const struct pqcp_sovereign_event *event, const char *key)
{
	for (size_t index = 0U; index < event->attribute_count; ++index) {
		if (strcmp(event->attributes[index].key, key) == 0) {
			return &event->attributes[index];
		}
	}
	return NULL;
}

ZTEST(pqcp_sovereign_audit, test_event_redact_modes)
{
	struct pqcp_sovereign_event source;
	struct pqcp_sovereign_event copy;
	struct pqcp_sovereign_event proj;
	struct pqcp_sovereign_event proj2;
	struct pqcp_sovereign_event other_tenant;
	const struct pqcp_sovereign_audit_attribute *attribute;
	uint8_t zero[DIGEST_BYTES] = { 0 };

	make_privacy_event(&source, "tenant-a");
	copy = source;

	/* NONE: faithful projection, still verifiable, not flagged redacted. */
	zassert_ok(pqcp_sovereign_event_redact(
		&source, PQCP_SOVEREIGN_AUDIT_REDACTION_NONE, true, true,
		&proj));
	zassert_ok(pqcp_sovereign_event_verify(&proj));
	zassert_str_equal(proj.actor, "alice");
	zassert_str_equal(proj.reason, "because");
	zassert_equal(proj.attribute_count, 4U);
	zassert_equal(proj.flags & PQCP_SOVEREIGN_AUDIT_EVENT_REDACTED, 0U);

	/* Reasons / attributes can be dropped independently of the mode. */
	zassert_ok(pqcp_sovereign_event_redact(
		&source, PQCP_SOVEREIGN_AUDIT_REDACTION_NONE, true, false,
		&proj));
	zassert_equal(proj.reason[0], '\0');
	zassert_equal(proj.attribute_count, 4U);
	zassert_ok(pqcp_sovereign_event_redact(
		&source, PQCP_SOVEREIGN_AUDIT_REDACTION_NONE, false, true,
		&proj));
	zassert_equal(proj.attribute_count, 0U);
	zassert_str_equal(proj.reason, "because");

	/* PSEUDONYMIZE */
	zassert_ok(pqcp_sovereign_event_redact(
		&source, PQCP_SOVEREIGN_AUDIT_REDACTION_PSEUDONYMIZE, true, true,
		&proj));
	zassert_true(is_pseudonym(proj.actor), "actor: %s", proj.actor);
	zassert_true(is_pseudonym(proj.object), "object: %s", proj.object);
	zassert_not_equal(strcmp(proj.actor, proj.object), 0);
	zassert_not_equal((proj.flags & PQCP_SOVEREIGN_AUDIT_EVENT_REDACTED), 0U);
	attribute = find_attribute(&proj, "p_email");
	zassert_not_null(attribute);
	zassert_equal(attribute->type, PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_DIGEST,
		      "personal text must become a digest");
	attribute = find_attribute(&proj, "q_note");
	zassert_not_null(attribute);
	zassert_equal(attribute->type, PQCP_SOVEREIGN_AUDIT_ATTRIBUTE_TEXT);
	zassert_str_equal(attribute->value.text, "public-note");
	attribute = find_attribute(&proj, "s_count");
	zassert_not_null(attribute);
	zassert_equal(attribute->value.u64, 9U);
	/* Deterministic and tenant-scoped. */
	zassert_ok(pqcp_sovereign_event_redact(
		&source, PQCP_SOVEREIGN_AUDIT_REDACTION_PSEUDONYMIZE, true, true,
		&proj2));
	zassert_str_equal(proj.actor, proj2.actor);
	make_privacy_event(&other_tenant, "tenant-b");
	zassert_ok(pqcp_sovereign_event_redact(
		&other_tenant, PQCP_SOVEREIGN_AUDIT_REDACTION_PSEUDONYMIZE, true,
		true, &proj2));
	zassert_not_equal(strcmp(proj.actor, proj2.actor), 0,
			  "pseudonyms must not correlate across tenants");

	/* MINIMIZE */
	zassert_ok(pqcp_sovereign_event_redact(
		&source, PQCP_SOVEREIGN_AUDIT_REDACTION_MINIMIZE, true, true,
		&proj));
	zassert_equal(proj.actor[0], '\0');
	zassert_equal(proj.reason[0], '\0');
	zassert_str_equal(proj.object, "key/1");
	zassert_not_equal((proj.flags & PQCP_SOVEREIGN_AUDIT_EVENT_REDACTED), 0U);
	zassert_is_null(find_attribute(&proj, "p_email"));
	zassert_is_null(find_attribute(&proj, "r_secret"));
	zassert_not_null(find_attribute(&proj, "q_note"));
	zassert_not_null(find_attribute(&proj, "s_count"));
	zassert_equal(proj.attribute_count, 2U);

	/* STRICT */
	zassert_ok(pqcp_sovereign_event_redact(
		&source, PQCP_SOVEREIGN_AUDIT_REDACTION_STRICT, true, true,
		&proj));
	zassert_equal(proj.actor[0], '\0');
	zassert_equal(proj.object[0], '\0');
	zassert_equal(proj.reason[0], '\0');
	zassert_str_equal(proj.source, "redacted");
	zassert_equal(proj.attribute_count, 0U);
	zassert_mem_equal(proj.actor_digest, zero, DIGEST_BYTES);
	zassert_mem_equal(proj.subject_digest, zero, DIGEST_BYTES);
	zassert_not_equal((proj.flags & PQCP_SOVEREIGN_AUDIT_EVENT_REDACTED), 0U);
	/* Class, outcome, severity and ids survive every mode. */
	zassert_equal(proj.event_class, source.event_class);
	zassert_equal(proj.severity, source.severity);
	zassert_equal(proj.outcome, source.outcome);
	zassert_mem_equal(proj.event_id, source.event_id,
			  sizeof(source.event_id));

	/* The source is never modified by projection. */
	zassert_ok(pqcp_sovereign_event_verify(&source));
	zassert_str_equal(source.actor, copy.actor);
	zassert_str_equal(source.reason, copy.reason);
	zassert_equal(source.attribute_count, copy.attribute_count);
	zassert_equal(source.flags, copy.flags);
}

ZTEST(pqcp_sovereign_audit, test_event_redact_negative_paths)
{
	struct pqcp_sovereign_event source;
	struct pqcp_sovereign_event proj;
	struct pqcp_sovereign_event fresh;

	append_events(0U, 1U, &source);
	zassert_equal(pqcp_sovereign_event_redact(
		NULL, PQCP_SOVEREIGN_AUDIT_REDACTION_NONE, true, true, &proj),
		-EINVAL);
	zassert_equal(pqcp_sovereign_event_redact(
		&source, PQCP_SOVEREIGN_AUDIT_REDACTION_NONE, true, true, NULL),
		-EINVAL);
	zassert_equal(pqcp_sovereign_event_redact(
		&source, (enum pqcp_sovereign_audit_redaction)4, true, true,
		&proj), -EINVAL);
	zassert_equal(pqcp_sovereign_event_redact(
		&source, (enum pqcp_sovereign_audit_redaction)-1, true, true,
		&proj), -EINVAL);
	zassert_equal(pqcp_sovereign_event_redact(
		&source, (enum pqcp_sovereign_audit_redaction)99, true, true,
		&proj), -EINVAL);

	make_event(&fresh, 0U);
	zassert_equal(pqcp_sovereign_event_redact(
		&fresh, PQCP_SOVEREIGN_AUDIT_REDACTION_NONE, true, true, &proj),
		-EINVAL, "uncommitted source");
	fresh = source;
	fresh.schema_version = 0U;
	zassert_equal(pqcp_sovereign_event_redact(
		&fresh, PQCP_SOVEREIGN_AUDIT_REDACTION_STRICT, true, true,
		&proj), -EINVAL);
}

/* ------------------------------------------------------------------ */
/* Ledger                                                              */
/* ------------------------------------------------------------------ */

ZTEST(pqcp_sovereign_audit, test_ledger_init_validation)
{
	struct pqcp_sovereign_event_ledger local;
	uint64_t first = 0U;
	uint64_t last = 0U;
	struct pqcp_sovereign_event_ledger_snapshot snapshot;
	uint8_t zero_anchor[DIGEST_BYTES] = { 0 };

	memset(anchor, 0x3c, sizeof(anchor));
	zassert_equal(pqcp_sovereign_event_ledger_init(
		NULL, ledger_storage, 4U, 1U, anchor), -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_init(
		&local, NULL, 4U, 1U, anchor), -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_init(
		&local, ledger_storage, 0U, 1U, anchor), -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_init(
		&local, ledger_storage, 4U, 0U, anchor), -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_init(
		&local, ledger_storage, 4U, 1U, NULL), -EINVAL);

	/* Storage is zeroed by init so no stale event can be adopted. */
	memset(ledger_storage, 0xff, sizeof(ledger_storage));
	zassert_ok(pqcp_sovereign_event_ledger_init(
		&local, ledger_storage, 4U, 100U, anchor));
	for (size_t index = 0U; index < 4U; ++index) {
		zassert_false(ledger_storage[index].occupied);
		zassert_equal(ledger_storage[index].sequence, 0U);
	}
	zassert_ok(pqcp_sovereign_event_ledger_verify(&local));
	zassert_ok(pqcp_sovereign_event_ledger_bounds(&local, &first, &last));
	zassert_equal(first, 100U, "empty ledger reports the next sequence");
	zassert_equal(last, 0U);
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&local, &snapshot));
	zassert_equal(snapshot.count, 0U);
	zassert_equal(snapshot.capacity, 4U);
	zassert_equal(snapshot.next_sequence, 100U);
	zassert_equal(snapshot.appended_count, 0U);
	zassert_equal(snapshot.evicted_count, 0U);
	zassert_equal(snapshot.rejected_count, 0U);
	zassert_equal(snapshot.schema_version,
		      PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION);
	zassert_mem_equal(snapshot.anchor_digest, anchor, DIGEST_BYTES);
	zassert_mem_equal(snapshot.chain_head, anchor, DIGEST_BYTES,
			  "empty chain head is the anchor");

	/* All-zero anchor is accepted (genesis ledger). */
	zassert_ok(pqcp_sovereign_event_ledger_init(
		&local, ledger_storage, 4U, 1U, zero_anchor));
	zassert_ok(pqcp_sovereign_event_ledger_verify(&local));

	/* Re-initialisation discards previous content. */
	reset_ledger(4U, 1U);
	append_events(0U, 3U, NULL);
	zassert_equal(ledger.count, 3U);
	reset_ledger(4U, 1U);
	zassert_equal(ledger.count, 0U);
	zassert_equal(ledger.appended_count, 0U);
	zassert_ok(pqcp_sovereign_event_ledger_verify(&ledger));
}

ZTEST(pqcp_sovereign_audit, test_ledger_append_chain_and_lookup)
{
	struct pqcp_sovereign_event committed[4];
	struct pqcp_sovereign_event fetched;
	struct pqcp_sovereign_event_ledger_snapshot snapshot;
	uint64_t first = 0U;
	uint64_t last = 0U;
	uint8_t expected_previous[DIGEST_BYTES];

	reset_ledger(8U, 10U);
	memcpy(expected_previous, anchor, DIGEST_BYTES);
	for (size_t index = 0U; index < 4U; ++index) {
		struct pqcp_sovereign_event event;

		make_event(&event, index);
		zassert_ok(pqcp_sovereign_event_ledger_append(
			&ledger, &event, &committed[index]));
		zassert_equal(committed[index].sequence, 10U + index,
			      "sequences are dense and ledger-assigned");
		zassert_true(committed[index].occupied);
		zassert_mem_equal(committed[index].previous_digest,
				  expected_previous, DIGEST_BYTES,
				  "event %zu is chained to its predecessor",
				  index);
		zassert_ok(pqcp_sovereign_event_verify(&committed[index]));
		memcpy(expected_previous, committed[index].event_digest,
		       DIGEST_BYTES);
		/* The caller's event is not mutated by append. */
		zassert_equal(event.sequence, 0U);
		zassert_false(event.occupied);
	}
	zassert_ok(pqcp_sovereign_event_ledger_verify(&ledger));

	/* A NULL out-parameter is allowed. */
	{
		struct pqcp_sovereign_event event;

		make_event(&event, 4U);
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
							      NULL));
	}
	zassert_equal(ledger.count, 5U);

	for (size_t index = 0U; index < 4U; ++index) {
		zassert_ok(pqcp_sovereign_event_ledger_get(
			&ledger, 10U + index, &fetched));
		zassert_equal(fetched.sequence, 10U + index);
		zassert_mem_equal(fetched.event_digest,
				  committed[index].event_digest, DIGEST_BYTES);
		zassert_str_equal(fetched.reason, "because");
	}
	zassert_ok(pqcp_sovereign_event_ledger_bounds(&ledger, &first, &last));
	zassert_equal(first, 10U);
	zassert_equal(last, 14U);

	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &snapshot));
	zassert_equal(snapshot.count, 5U);
	zassert_equal(snapshot.first_sequence, 10U);
	zassert_equal(snapshot.last_sequence, 14U);
	zassert_equal(snapshot.next_sequence, 15U);
	zassert_equal(snapshot.appended_count, 5U);
	zassert_equal(snapshot.evicted_count, 0U);
	zassert_equal(snapshot.generation, 6U, "generation bumps per append");
	zassert_mem_equal(snapshot.anchor_digest, anchor, DIGEST_BYTES);
	zassert_mem_equal(snapshot.chain_head, ledger.chain_head,
			  DIGEST_BYTES);

	/* Lookup misses. */
	zassert_equal(pqcp_sovereign_event_ledger_get(&ledger, 0U, &fetched),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_get(&ledger, 9U, &fetched),
		      -ESTALE);
	zassert_equal(pqcp_sovereign_event_ledger_get(&ledger, 15U, &fetched),
		      -ENOENT);
	zassert_equal(pqcp_sovereign_event_ledger_get(&ledger, UINT64_MAX,
						      &fetched), -ENOENT);
}

ZTEST(pqcp_sovereign_audit, test_ledger_append_rejects_invalid_events)
{
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event committed;
	struct pqcp_sovereign_event bad;
	struct pqcp_sovereign_event_ledger_snapshot before;
	struct pqcp_sovereign_event_ledger_snapshot after;
	uint64_t rejected = 0U;

	append_events(0U, 1U, &committed);
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &before));
	make_event(&event, 1U);

#define EXPECT_APPEND_REJECTED(expected, mutation)                             \
	do {                                                                   \
		bad = event;                                                   \
		mutation;                                                      \
		zassert_equal(pqcp_sovereign_event_ledger_append(              \
				      &ledger, &bad, NULL),                    \
			      (expected), "append result for " #mutation);     \
		rejected++;                                                    \
		zassert_equal(ledger.rejected_count, rejected,                 \
			      "rejected_count after " #mutation);              \
		zassert_equal(ledger.count, 1U);                               \
		zassert_equal(ledger.next_sequence, 2U);                       \
	} while (0)

	EXPECT_APPEND_REJECTED(-EINVAL, bad.sequence = 5U);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.occupied = true);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.schema_version = 2U);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.generation = 0U);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.observed_at_ms = 0U);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.ingested_at_ms =
					       bad.observed_at_ms - 1U);
	EXPECT_APPEND_REJECTED(-EINVAL, memset(bad.event_id, 0,
					       sizeof(bad.event_id)));
	EXPECT_APPEND_REJECTED(-EINVAL, bad.policy_epoch++);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.revocation_epoch++);
	EXPECT_APPEND_REJECTED(-EBADMSG, bad.tenant.tenant_id[0] = 'T');
	EXPECT_APPEND_REJECTED(-EBADMSG, bad.tenant.scope_digest[0] ^= 1U);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.event_class =
					       PQCP_SOVEREIGN_AUDIT_CLASS_COUNT);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.activity =
					       PQCP_SOVEREIGN_AUDIT_ACTIVITY_NONE);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.severity =
					       (enum pqcp_sovereign_audit_severity)9);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.outcome =
					       (enum pqcp_sovereign_audit_outcome)9);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.data_class =
					       PQCP_SOVEREIGN_AUDIT_DATA_CLASS_COUNT);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.flags = (1U << 12));
	EXPECT_APPEND_REJECTED(-EINVAL, bad.source[0] = '\n');
	EXPECT_APPEND_REJECTED(-EINVAL, bad.source[0] = '\0');
	EXPECT_APPEND_REJECTED(-EINVAL, bad.expires_at_ms = bad.observed_at_ms);
	EXPECT_APPEND_REJECTED(-EINVAL, bad.attribute_count =
					       PQCP_SOVEREIGN_AUDIT_MAX_ATTRIBUTES + 1U);

	/* Unsorted attributes cannot be committed. */
	zassert_ok(pqcp_sovereign_event_add_u64(&event, "aa", 1U, 0U));
	zassert_ok(pqcp_sovereign_event_add_u64(&event, "bb", 2U, 0U));
	{
		struct pqcp_sovereign_audit_attribute swap = event.attributes[0];

		event.attributes[0] = event.attributes[1];
		event.attributes[1] = swap;
	}
	EXPECT_APPEND_REJECTED(-EBADMSG, (void)0);

	/* Argument validation (does not touch the ledger counters). */
	make_event(&event, 1U);
	zassert_equal(pqcp_sovereign_event_ledger_append(NULL, &event, NULL),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_append(&ledger, NULL, NULL),
		      -EINVAL);
	/* Re-appending a committed event is refused (no double commit). */
	zassert_equal(pqcp_sovereign_event_ledger_append(&ledger, &committed,
							 NULL), -EINVAL);
	rejected++; /* reaches staging, so it is counted as a rejection */

	/* Nothing leaked into the chain: head, anchor and verification hold. */
	zassert_ok(pqcp_sovereign_event_ledger_verify(&ledger));
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &after));
	zassert_mem_equal(after.chain_head, before.chain_head, DIGEST_BYTES);
	zassert_equal(after.appended_count, before.appended_count);
	zassert_equal(after.generation, before.generation,
		      "rejections do not advance the generation");
	zassert_equal(after.rejected_count, rejected);
	zassert_not_equal(memcmp(after.snapshot_digest, before.snapshot_digest,
				 DIGEST_BYTES), 0,
			  "rejected_count is bound by the snapshot digest");
}

ZTEST(pqcp_sovereign_audit, test_ledger_capacity_eviction_and_anchor)
{
	struct pqcp_sovereign_event committed[6];
	struct pqcp_sovereign_event fetched;
	struct pqcp_sovereign_event_ledger_snapshot snapshot;
	uint64_t first = 0U;
	uint64_t last = 0U;

	reset_ledger(3U, 1U);
	for (size_t index = 0U; index < 5U; ++index) {
		struct pqcp_sovereign_event event;

		make_event(&event, index);
		zassert_ok(pqcp_sovereign_event_ledger_append(
			&ledger, &event, &committed[index]));
		zassert_true(ledger.count <= 3U);
		zassert_ok(pqcp_sovereign_event_ledger_verify(&ledger));
	}
	zassert_equal(ledger.count, 3U);
	zassert_equal(ledger.evicted_count, 2U);
	zassert_equal(ledger.appended_count, 5U);
	zassert_ok(pqcp_sovereign_event_ledger_bounds(&ledger, &first, &last));
	zassert_equal(first, 3U);
	zassert_equal(last, 5U);

	/* Evicted entries report as stale, live ones round-trip. */
	zassert_equal(pqcp_sovereign_event_ledger_get(&ledger, 1U, &fetched),
		      -ESTALE);
	zassert_equal(pqcp_sovereign_event_ledger_get(&ledger, 2U, &fetched),
		      -ESTALE);
	zassert_ok(pqcp_sovereign_event_ledger_get(&ledger, 3U, &fetched));
	zassert_mem_equal(fetched.event_digest, committed[2].event_digest,
			  DIGEST_BYTES);
	zassert_ok(pqcp_sovereign_event_ledger_get(&ledger, 5U, &fetched));
	zassert_mem_equal(fetched.event_digest, committed[4].event_digest,
			  DIGEST_BYTES);
	zassert_equal(pqcp_sovereign_event_ledger_get(&ledger, 6U, &fetched),
		      -ENOENT);

	/* The anchor advanced to the digest of the last evicted event so the
	 * surviving window still chains back to something verifiable.
	 */
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &snapshot));
	zassert_mem_equal(snapshot.anchor_digest, committed[1].event_digest,
			  DIGEST_BYTES);
	zassert_mem_equal(fetched.previous_digest, committed[3].event_digest,
			  DIGEST_BYTES);
	zassert_equal(snapshot.first_sequence, 3U);
	zassert_equal(snapshot.evicted_count, 2U);
	zassert_equal(snapshot.count, 3U);
	zassert_equal(snapshot.capacity, 3U);

	/* Capacity one: every append evicts. */
	reset_ledger(1U, 1U);
	append_events(0U, 4U, &fetched);
	zassert_equal(ledger.count, 1U);
	zassert_equal(ledger.evicted_count, 3U);
	zassert_equal(fetched.sequence, 4U);
	zassert_ok(pqcp_sovereign_event_ledger_verify(&ledger));
	zassert_ok(pqcp_sovereign_event_ledger_bounds(&ledger, &first, &last));
	zassert_equal(first, 4U);
	zassert_equal(last, 4U);
}

ZTEST(pqcp_sovereign_audit, test_ledger_ring_wraparound_integrity)
{
	struct pqcp_sovereign_event fetched;
	uint64_t first = 0U;
	uint64_t last = 0U;

	reset_ledger(5U, 1U);
	append_events(0U, 23U, NULL);
	zassert_equal(ledger.count, 5U);
	zassert_ok(pqcp_sovereign_event_ledger_verify(&ledger));
	zassert_ok(pqcp_sovereign_event_ledger_bounds(&ledger, &first, &last));
	zassert_equal(first, 19U);
	zassert_equal(last, 23U);
	for (uint64_t sequence = first; sequence <= last; ++sequence) {
		zassert_ok(pqcp_sovereign_event_ledger_get(&ledger, sequence,
							   &fetched));
		zassert_equal(fetched.sequence, sequence);
		zassert_ok(pqcp_sovereign_event_verify(&fetched));
		/* observed_at_ms encodes the originating index: n = seq - 1 */
		zassert_equal(fetched.observed_at_ms, 1000U + sequence - 1U);
	}
	/* Hash links hold across the physical wrap point. */
	for (uint64_t sequence = first + 1U; sequence <= last; ++sequence) {
		struct pqcp_sovereign_event prev;

		zassert_ok(pqcp_sovereign_event_ledger_get(
			&ledger, sequence - 1U, &prev));
		zassert_ok(pqcp_sovereign_event_ledger_get(
			&ledger, sequence, &fetched));
		zassert_mem_equal(fetched.previous_digest, prev.event_digest,
				  DIGEST_BYTES);
	}
	zassert_equal(ledger.appended_count, 23U);
	zassert_equal(ledger.evicted_count, 18U);
}

ZTEST(pqcp_sovereign_audit, test_ledger_sequence_exhaustion)
{
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event committed;

	/* The reserved terminal sequence value is never assigned. */
	reset_ledger(4U, UINT64_MAX);
	make_event(&event, 0U);
	zassert_equal(pqcp_sovereign_event_ledger_append(&ledger, &event, NULL),
		      -EOVERFLOW);
	zassert_equal(ledger.count, 0U);
	zassert_equal(ledger.rejected_count, 1U);
	zassert_ok(pqcp_sovereign_event_ledger_verify(&ledger));

	/* One slot left: it is used, then the ledger refuses further appends. */
	reset_ledger(4U, UINT64_MAX - 1U);
	zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
						      &committed));
	zassert_equal(committed.sequence, UINT64_MAX - 1U);
	make_event(&event, 1U);
	zassert_equal(pqcp_sovereign_event_ledger_append(&ledger, &event, NULL),
		      -EOVERFLOW);
	zassert_equal(ledger.count, 1U);
	zassert_equal(ledger.rejected_count, 1U);
	zassert_ok(pqcp_sovereign_event_ledger_verify(&ledger));
}

ZTEST(pqcp_sovereign_audit, test_ledger_tamper_detection)
{
	struct pqcp_sovereign_event *entry;
	struct pqcp_sovereign_event_ledger_snapshot clean;
	struct pqcp_sovereign_event_ledger_snapshot dirty;

	/* Baseline is clean. */
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	zassert_ok(pqcp_sovereign_event_ledger_verify(&ledger));
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &clean));

	/* 1. In-place payload edit of a middle entry. */
	entry = physical_event(2U);
	zassert_not_null(entry);
	entry->reason[0] = 'X';
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EBADMSG);

	/* 2. Rewrite attack: edit AND recompute the event digest.  The edit is
	 * detected via the successor's previous_digest link.
	 */
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	entry = physical_event(2U);
	entry->reason[0] = 'X';
	zassert_ok(pqcp_sovereign_event_digest(entry, entry->event_digest));
	zassert_ok(pqcp_sovereign_event_verify(entry),
		   "the forged entry is self-consistent");
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EBADMSG);

	/* 3. Same rewrite on the newest entry: caught by the chain head. */
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	entry = physical_event(4U);
	entry->reason[0] = 'X';
	zassert_ok(pqcp_sovereign_event_digest(entry, entry->event_digest));
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EBADMSG);

	/* 4. Rewrite of the oldest entry: caught by the anchor/link check
	 * against its successor.
	 */
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	entry = physical_event(1U);
	entry->reason[0] = 'X';
	zassert_ok(pqcp_sovereign_event_digest(entry, entry->event_digest));
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EBADMSG);

	/* 5. Reorder two entries. */
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	{
		struct pqcp_sovereign_event tmp = ledger_storage[1];

		ledger_storage[1] = ledger_storage[2];
		ledger_storage[2] = tmp;
	}
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EBADMSG);

	/* 6. Broken link in previous_digest. */
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	physical_event(3U)->previous_digest[0] ^= 0x01U;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EBADMSG);

	/* 7. Chain head, anchor and tail truncation. */
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	ledger.chain_head[7] ^= 0x01U;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EBADMSG);
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &dirty));
	zassert_not_equal(memcmp(dirty.snapshot_digest, clean.snapshot_digest,
				 DIGEST_BYTES), 0,
			  "snapshot digest must expose a forged chain head");

	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	ledger.anchor_digest[0] ^= 0x01U;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EBADMSG);

	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	ledger.count--;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EBADMSG,
		      "silently dropping the newest entry is detected");

	/* 8. Slot cleared (event removed but counters untouched). */
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	physical_event(2U)->occupied = false;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EBADMSG);

	/* 9. Control-structure corruption. */
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	ledger.count = ledger.capacity + 1U;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EINVAL);
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	ledger.head = ledger.capacity;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EINVAL);
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	ledger.next_sequence = 0U;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EINVAL);
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	ledger.next_sequence++;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EBADMSG);
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	ledger.appended_count = 1U;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EINVAL);
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	ledger.schema_version = 9U;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EINVAL);
	reset_ledger(4U, 1U);
	append_events(0U, 4U, NULL);
	ledger.generation = 0U;
	zassert_equal(pqcp_sovereign_event_ledger_verify(&ledger), -EINVAL);

	/* 10. Tamper detection survives eviction/wrap (anchor chain). */
	reset_ledger(3U, 1U);
	append_events(0U, 8U, NULL);
	zassert_ok(pqcp_sovereign_event_ledger_verify(&ledger));
	entry = physical_event(7U);
	entry->severity = PQCP_SOVEREIGN_AUDIT_SEVERITY_LOW;
	zassert_not_equal(pqcp_sovereign_event_ledger_verify(&ledger), 0);
}

ZTEST(pqcp_sovereign_audit, test_ledger_append_refuses_corrupt_eviction)
{
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event_ledger_snapshot before;
	struct pqcp_sovereign_event_ledger_snapshot after;

	reset_ledger(2U, 1U);
	append_events(0U, 2U, NULL);
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &before));

	/* Corrupt the entry that the next append would evict. */
	ledger.events[ledger.head].reason[0] ^= 0x01U;
	make_event(&event, 2U);
	zassert_equal(pqcp_sovereign_event_ledger_append(&ledger, &event, NULL),
		      -EBADMSG, "a corrupt entry must not become the anchor");
	zassert_equal(ledger.count, 2U);
	zassert_equal(ledger.appended_count, 2U);
	zassert_equal(ledger.evicted_count, 0U);
	zassert_equal(ledger.rejected_count, 1U);
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &after));
	zassert_mem_equal(after.chain_head, before.chain_head, DIGEST_BYTES);
	zassert_mem_equal(after.anchor_digest, before.anchor_digest,
			  DIGEST_BYTES);
	zassert_equal(after.next_sequence, before.next_sequence);

	/* Slot flagged unoccupied at the head behaves the same. */
	reset_ledger(2U, 1U);
	append_events(0U, 2U, NULL);
	ledger.events[ledger.head].occupied = false;
	make_event(&event, 2U);
	zassert_equal(pqcp_sovereign_event_ledger_append(&ledger, &event, NULL),
		      -EBADMSG);
}

ZTEST(pqcp_sovereign_audit, test_ledger_snapshot_and_bounds)
{
	struct pqcp_sovereign_event_ledger_snapshot a;
	struct pqcp_sovereign_event_ledger_snapshot b;
	struct pqcp_sovereign_event_ledger_snapshot c;
	uint64_t first = 7U;
	uint64_t last = 7U;

	reset_ledger(4U, 5U);
	zassert_ok(pqcp_sovereign_event_ledger_bounds(&ledger, &first, &last));
	zassert_equal(first, 5U);
	zassert_equal(last, 0U);

	append_events(0U, 2U, NULL);
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &a));
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &b));
	zassert_mem_equal(a.snapshot_digest, b.snapshot_digest, DIGEST_BYTES,
			  "snapshots of an unchanged ledger are identical");
	zassert_equal(a.first_sequence, 5U);
	zassert_equal(a.last_sequence, 6U);
	zassert_equal(a.next_sequence, 7U);
	zassert_equal(a.count, 2U);

	append_events(2U, 1U, NULL);
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &c));
	zassert_not_equal(memcmp(a.snapshot_digest, c.snapshot_digest,
				 DIGEST_BYTES), 0);
	zassert_not_equal(memcmp(a.chain_head, c.chain_head, DIGEST_BYTES), 0);
	zassert_true(c.generation > a.generation);

	/* The snapshot digest is bound to every scalar: forge each and compare
	 * against the genuine one by editing a copy of the ledger view.
	 */
	ledger.rejected_count++;
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &b));
	zassert_not_equal(memcmp(b.snapshot_digest, c.snapshot_digest,
				 DIGEST_BYTES), 0);
	ledger.rejected_count--;
	ledger.evicted_count++;
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &b));
	zassert_not_equal(memcmp(b.snapshot_digest, c.snapshot_digest,
				 DIGEST_BYTES), 0);
	ledger.evicted_count--;
	zassert_ok(pqcp_sovereign_event_ledger_snapshot(&ledger, &b));
	zassert_mem_equal(b.snapshot_digest, c.snapshot_digest, DIGEST_BYTES);
}

ZTEST(pqcp_sovereign_audit, test_ledger_null_and_uninitialized_args)
{
	struct pqcp_sovereign_event_ledger raw;
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event out;
	struct pqcp_sovereign_event_ledger_snapshot snapshot;
	uint64_t first = 0U;
	uint64_t last = 0U;

	append_events(0U, 1U, NULL);
	make_event(&event, 5U);

	/* NULL arguments */
	zassert_equal(pqcp_sovereign_event_ledger_get(NULL, 1U, &out), -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_get(&ledger, 1U, NULL),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_bounds(NULL, &first, &last),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_bounds(&ledger, NULL, &last),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_bounds(&ledger, &first, NULL),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_snapshot(NULL, &snapshot),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_snapshot(&ledger, NULL),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_verify(NULL), -EINVAL);

	/* A zeroed (never initialised) ledger is refused by every entry point,
	 * without touching its (non-existent) mutex.
	 */
	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_sovereign_event_ledger_append(&raw, &event, NULL),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_get(&raw, 1U, &out), -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_bounds(&raw, &first, &last),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_snapshot(&raw, &snapshot),
		      -EINVAL);
	zassert_equal(pqcp_sovereign_event_ledger_verify(&raw), -EINVAL);

	/* Empty ledger: no event can be fetched. */
	reset_ledger(4U, 1U);
	zassert_not_equal(pqcp_sovereign_event_ledger_get(&ledger, 1U, &out), 0);
}

/* ------------------------------------------------------------------ */
/* CEF                                                                 */
/* ------------------------------------------------------------------ */

static void append_cat(char *destination, size_t capacity, const char *text)
{
	size_t used = strlen(destination);

	zassert_true(used + strlen(text) + 1U <= capacity);
	strcpy(destination + used, text);
}

ZTEST(pqcp_sovereign_audit, test_cef_event_byte_exact)
{
	struct pqcp_sovereign_event event;
	char hex[DIGEST_BYTES * 2U + 1U];
	size_t length = 0U;

	append_events(0U, 1U, &event);
	zassert_ok(pqcp_sovereign_audit_cef_encode_event(
		&event, out_buf, sizeof(out_buf), &length));

	scratch[0] = '\0';
	append_cat(scratch, sizeof(scratch),
		   "<131>1 - - pqcp-sovereign - deployment - "
		   "CEF:0|PQCP|ZephyrTrustStack|1|deployment|deploy|8|"
		   "rt=1000 end=1005 cn1=1 cn1Label=eventSequence cn2=7 "
		   "cn2Label=policyEpoch cn3=3 cn3Label=revocationEpoch "
		   "suid=tenant-a sourceServiceName=unit suser=alice "
		   "dobj=key/1 act=sign outcome=success reasonCode=0 "
		   "msg=because externalId=4242 flexNumber1=5 "
		   "flexNumber1Label=eventFlags flexNumber2=2 "
		   "flexNumber2Label=dataClass eventId=");
	hex_encode(event.event_id, sizeof(event.event_id), hex);
	append_cat(scratch, sizeof(scratch), hex);
	append_cat(scratch, sizeof(scratch), " eventDigest=");
	hex_encode(event.event_digest, DIGEST_BYTES, hex);
	append_cat(scratch, sizeof(scratch), hex);
	append_cat(scratch, sizeof(scratch), " previousDigest=");
	hex_encode(event.previous_digest, DIGEST_BYTES, hex);
	append_cat(scratch, sizeof(scratch), hex);
	append_cat(scratch, sizeof(scratch), " evidenceDigest=");
	hex_encode(event.evidence_digest, DIGEST_BYTES, hex);
	append_cat(scratch, sizeof(scratch), hex);
	append_cat(scratch, sizeof(scratch), " receiptDigest=");
	hex_encode(event.receipt_digest, DIGEST_BYTES, hex);
	append_cat(scratch, sizeof(scratch), hex);
	append_cat(scratch, sizeof(scratch), " resourceDigest=");
	hex_encode(event.resource_digest, DIGEST_BYTES, hex);
	append_cat(scratch, sizeof(scratch), hex);

	zassert_equal(length, strlen(scratch), "length %zu vs expected %zu",
		      length, strlen(scratch));
	zassert_mem_equal(out_buf, scratch, length);
	/* Output is a single record: no line terminator, no NUL. */
	zassert_equal(count_byte(out_buf, length, '\n'), 0U);
	zassert_equal(count_byte(out_buf, length, '\0'), 0U);
}

ZTEST(pqcp_sovereign_audit, test_cef_event_escaping)
{
	struct pqcp_sovereign_event_draft draft;
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event committed;
	struct pqcp_sovereign_event forged;
	size_t length = 0U;

	fill_draft(&draft, 0U);
	draft.actor = "a=b\\c";
	draft.object = "k|1=2";
	draft.reason = "x|y=z\\";
	draft.source = "src=1";
	zassert_ok(pqcp_sovereign_event_init(&event, &draft));
	zassert_ok(pqcp_sovereign_event_add_text(&event, "d_text", "p=1\\q|r", 0U));
	zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
						      &committed));
	zassert_ok(pqcp_sovereign_audit_cef_encode_event(
		&committed, out_buf, sizeof(out_buf), &length));

	/* '=' and '\' are escaped in extension values; '|' is only special in
	 * the header and passes through verbatim in extensions.
	 */
	zassert_true(has(out_buf, length, "suser=a\\=b\\\\c "), "suser");
	zassert_true(has(out_buf, length, "dobj=k|1\\=2 "), "dobj");
	zassert_true(has(out_buf, length, "msg=x|y\\=z\\\\ "), "msg");
	zassert_true(has(out_buf, length, "sourceServiceName=src\\=1 "), "src");
	zassert_true(has(out_buf, length, "pqcp_d_text=p\\=1\\\\q|r"), "attr");
	/* Header is exactly seven '|'-terminated fields before extensions. */
	zassert_true(has(out_buf, length,
			 "CEF:0|PQCP|ZephyrTrustStack|1|deployment|deploy|8|rt="));

	/* Raw control characters (forged directly in the struct, since the
	 * constructors refuse them) must be neutralised to the two-character
	 * sequence backslash-n and never emit a real line break.
	 */
	forged = committed;
	memset(forged.reason, 0, sizeof(forged.reason));
	memcpy(forged.reason, "l1\nl2\rl3", 8U);
	memset(forged.actor, 0, sizeof(forged.actor));
	memcpy(forged.actor, "u\r\nv", 4U);
	zassert_ok(pqcp_sovereign_audit_cef_encode_event(
		&forged, out_buf, sizeof(out_buf), &length));
	zassert_equal(count_byte(out_buf, length, '\n'), 0U);
	zassert_equal(count_byte(out_buf, length, '\r'), 0U);
	zassert_true(has(out_buf, length, "msg=l1\\nl2\\nl3 "));
	zassert_true(has(out_buf, length, "suser=u\\n\\nv "));

	/* Extension key hygiene: attribute keys are prefixed pqcp_. */
	zassert_true(has(out_buf, length, " pqcp_d_text="));
}

ZTEST(pqcp_sovereign_audit, test_cef_attribute_types_and_severity_mapping)
{
	struct pqcp_sovereign_event_draft draft;
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event committed;
	char hex[DIGEST_BYTES * 2U + 1U];
	uint8_t digest[DIGEST_BYTES];
	size_t length = 0U;
	static const struct {
		enum pqcp_sovereign_audit_severity severity;
		const char *prefix;
	} table[] = {
		{ PQCP_SOVEREIGN_AUDIT_SEVERITY_UNKNOWN,
		  "<135>1 - - pqcp-sovereign - deployment - "
		  "CEF:0|PQCP|ZephyrTrustStack|1|deployment|deploy|0|" },
		{ PQCP_SOVEREIGN_AUDIT_SEVERITY_INFORMATIONAL,
		  "<134>1 - - pqcp-sovereign - deployment - "
		  "CEF:0|PQCP|ZephyrTrustStack|1|deployment|deploy|2|" },
		{ PQCP_SOVEREIGN_AUDIT_SEVERITY_LOW,
		  "<133>1 - - pqcp-sovereign - deployment - "
		  "CEF:0|PQCP|ZephyrTrustStack|1|deployment|deploy|4|" },
		{ PQCP_SOVEREIGN_AUDIT_SEVERITY_MEDIUM,
		  "<132>1 - - pqcp-sovereign - deployment - "
		  "CEF:0|PQCP|ZephyrTrustStack|1|deployment|deploy|6|" },
		{ PQCP_SOVEREIGN_AUDIT_SEVERITY_HIGH,
		  "<131>1 - - pqcp-sovereign - deployment - "
		  "CEF:0|PQCP|ZephyrTrustStack|1|deployment|deploy|8|" },
		{ PQCP_SOVEREIGN_AUDIT_SEVERITY_CRITICAL,
		  "<130>1 - - pqcp-sovereign - deployment - "
		  "CEF:0|PQCP|ZephyrTrustStack|1|deployment|deploy|10|" },
	};

	for (size_t index = 0U; index < ARRAY_SIZE(table); ++index) {
		reset_ledger(2U, 1U);
		fill_draft(&draft, 0U);
		draft.severity = table[index].severity;
		zassert_ok(pqcp_sovereign_event_init(&event, &draft));
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
							      &committed));
		zassert_ok(pqcp_sovereign_audit_cef_encode_event(
			&committed, out_buf, sizeof(out_buf), &length));
		zassert_equal(strncmp((const char *)out_buf, table[index].prefix,
				      strlen(table[index].prefix)), 0,
			      "severity %zu prefix mismatch", index);
	}

	/* Attribute value rendering for every type. */
	reset_ledger(2U, 1U);
	fill_draft(&draft, 0U);
	draft.result = -22;
	zassert_ok(pqcp_sovereign_event_init(&event, &draft));
	add_rich_attributes(&event);
	zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
						      &committed));
	zassert_ok(pqcp_sovereign_audit_cef_encode_event(
		&committed, out_buf, sizeof(out_buf), &length));
	zassert_true(has(out_buf, length, "reasonCode=-22 "));
	zassert_true(has(out_buf, length, "pqcp_a_u64=42"));
	zassert_true(has(out_buf, length, "pqcp_b_i64=-7"));
	zassert_true(has(out_buf, length, "pqcp_c_bool=true"));
	fill_digest(digest, 0x11U);
	hex_encode(digest, DIGEST_BYTES, hex);
	snprintf(scratch, sizeof(scratch), "pqcp_e_digest=%s", hex);
	zassert_true(has(out_buf, length, scratch));
	/* Attributes appear in sorted order after the fixed extensions. */
	zassert_true(find_bytes(out_buf, length, "pqcp_a_u64") <
		     find_bytes(out_buf, length, "pqcp_b_i64"));
	zassert_true(find_bytes(out_buf, length, "pqcp_b_i64") <
		     find_bytes(out_buf, length, "pqcp_e_digest"));
	zassert_true(find_bytes(out_buf, length, "resourceDigest=") <
		     find_bytes(out_buf, length, "pqcp_a_u64"));
}

ZTEST(pqcp_sovereign_audit, test_cef_event_buffer_boundaries_and_negatives)
{
	struct pqcp_sovereign_event event;

	append_events(0U, 1U, &event);
	event_encoder_negatives(pqcp_sovereign_audit_cef_encode_event);

	reset_ledger(8U, 1U);
	{
		struct pqcp_sovereign_event rich;

		make_event(&rich, 0U);
		add_rich_attributes(&rich);
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &rich,
							      &event));
	}
	(void)event_boundaries(pqcp_sovereign_audit_cef_encode_event, &event,
			       1U);
}

ZTEST(pqcp_sovereign_audit, test_cef_batch_structure_and_negatives)
{
	size_t length = 0U;
	char text[96];

	batch_encoder_negatives(pqcp_sovereign_audit_cef_encode_batch);

	reset_ledger(8U, 1U);
	append_events(0U, 3U, NULL);
	build_batch(3U, PQCP_SOVEREIGN_AUDIT_FORMAT_CEF_SYSLOG);
	zassert_ok(pqcp_sovereign_audit_cef_encode_batch(
		&batch, out_buf, sizeof(out_buf), &length));
	/* Summary + one record per event, newline separated. */
	zassert_equal(count_byte(out_buf, length, '\n'), 3U);
	zassert_equal(count_of(out_buf, length, "<131>1 - - pqcp-sovereign - "
					       "deployment - CEF:0|"), 3U);
	{
		static const char expected[] =
			"<134>1 - - pqcp-sovereign - audit_batch - "
			"CEF:0|PQCP|ZephyrTrustStack|1|audit_batch|export|2|"
			"rt=2000 externalId=77 suid=tenant-a cn1=1 "
			"cn1Label=firstSequence cn2=3 cn2Label=lastSequence "
			"cn3=3 cn3Label=scannedThroughSequence cnt=3 "
			"policyEpoch=7 redactionPolicy=0 sourceAnchorDigest=";

		zassert_true(length > sizeof(expected));
		zassert_equal(strncmp((const char *)out_buf, expected,
				      sizeof(expected) - 1U), 0);
	}
	hex_encode(batch.batch_digest, DIGEST_BYTES, text);
	snprintf(scratch, sizeof(scratch), "batchDigest=%s signatureAlgorithm=0",
		 text);
	zassert_true(has(out_buf, length, scratch));
	zassert_false(has(out_buf, length, "batchSignature="),
		      "no signature field when none is attached");
	zassert_true(has(out_buf, length, "eventSequence"));
	/* Events are emitted in batch order. */
	{
		const char *p1 = find_bytes(out_buf, length, "cn1=1 cn1Label=eventSequence");
		const char *p2 = find_bytes(out_buf, length, "cn1=2 cn1Label=eventSequence");
		const char *p3 = find_bytes(out_buf, length, "cn1=3 cn1Label=eventSequence");

		zassert_not_null(p1);
		zassert_not_null(p2);
		zassert_not_null(p3);
		zassert_true(p1 < p2 && p2 < p3);
	}

	/* Signature is rendered as lowercase hex when attached. */
	batch.signature_algorithm = PQCP_SOVEREIGN_AUDIT_SIGNATURE_MLDSA;
	batch.signature[0] = 0xde;
	batch.signature[1] = 0xad;
	batch.signature[2] = 0xbe;
	batch.signature[3] = 0xef;
	batch.signature_length = 4U;
	zassert_ok(pqcp_sovereign_audit_cef_encode_batch(
		&batch, out_buf, sizeof(out_buf), &length));
	zassert_true(has(out_buf, length, "signatureAlgorithm=1 "
					  "batchSignature=deadbeef\n"));

	/* Boundary sweep on a (small) batch. */
	build_batch(2U, PQCP_SOVEREIGN_AUDIT_FORMAT_CEF_SYSLOG);
	(void)batch_boundaries(pqcp_sovereign_audit_cef_encode_batch, &batch, 1U);
}

/* ------------------------------------------------------------------ */
/* OCSF                                                                */
/* ------------------------------------------------------------------ */

static void expect_json_with(const uint8_t *buffer, size_t length,
			     const char *needle)
{
	zassert_true(has(buffer, length, needle), "missing: %s", needle);
}

ZTEST(pqcp_sovereign_audit, test_ocsf_event_structure_and_json_valid)
{
	struct pqcp_sovereign_event event;
	char hex[DIGEST_BYTES * 2U + 1U];
	size_t length = 0U;

	{
		struct pqcp_sovereign_event draft_event;

		make_event(&draft_event, 0U);
		add_rich_attributes(&draft_event);
		zassert_ok(pqcp_sovereign_event_ledger_append(
			&ledger, &draft_event, &event));
	}
	zassert_ok(pqcp_sovereign_audit_ocsf_encode_event(
		&event, out_buf, sizeof(out_buf), &length));
	zassert_true(json_valid(out_buf, length), "invalid JSON: %.*s",
		     (int)length, (const char *)out_buf);
	zassert_equal(out_buf[0], '{');
	zassert_equal(out_buf[length - 1U], '}');
	zassert_equal(count_byte(out_buf, length, '\n'), 0U);

	/* Required OCSF base-event attributes. */
	expect_json_with(out_buf, length, "\"activity_id\":3,");
	expect_json_with(out_buf, length, "\"activity_name\":\"deploy\"");
	expect_json_with(out_buf, length, "\"category_uid\":5,");
	expect_json_with(out_buf, length, "\"class_uid\":5007,");
	expect_json_with(out_buf, length, "\"class_name\":\"deployment\"");
	expect_json_with(out_buf, length, "\"severity_id\":4,");
	expect_json_with(out_buf, length, "\"severity\":\"high\"");
	expect_json_with(out_buf, length, "\"status_id\":1,");
	expect_json_with(out_buf, length, "\"status\":\"success\"");
	expect_json_with(out_buf, length, "\"time\":1000,");
	expect_json_with(out_buf, length, "\"type_uid\":500703,");
	expect_json_with(out_buf, length, "\"message\":\"because\"");
	expect_json_with(out_buf, length,
			 "\"actor\":{\"user_name\":\"alice\",\"user_uid\":\"");
	expect_json_with(out_buf, length,
			 "\"tenant_uid\":\"tenant-a\",\"domain\":\"eu\"}");
	expect_json_with(out_buf, length,
			 "\"device\":{\"name\":\"unit\",\"type\":\"embedded\"");
	expect_json_with(out_buf, length,
			 "\"metadata\":{\"version\":\"1.4.0\","
			 "\"log_name\":\"pqcp_sovereign_audit\","
			 "\"log_provider\":\"PQCP\","
			 "\"product_name\":\"ZephyrTrustStack\","
			 "\"product_version\":\"1\",\"logged_time\":1005,"
			 "\"uid\":\"");
	hex_encode(event.event_id, sizeof(event.event_id), hex);
	snprintf(scratch, sizeof(scratch), "\"uid\":\"%s\"}", hex);
	expect_json_with(out_buf, length, scratch);
	hex_encode(event.event_digest, DIGEST_BYTES, hex);
	snprintf(scratch, sizeof(scratch), "\"event_digest\":\"%s\"", hex);
	expect_json_with(out_buf, length, scratch);
	hex_encode(event.previous_digest, DIGEST_BYTES, hex);
	snprintf(scratch, sizeof(scratch), "\"previous_digest\":\"%s\"", hex);
	expect_json_with(out_buf, length, scratch);

	/* Vendor extension block with typed attributes. */
	expect_json_with(out_buf, length, "\"unmapped\":{\"schema_version\":1,"
					  "\"generation\":1,\"sequence\":1,");
	expect_json_with(out_buf, length, "\"policy_epoch\":7,");
	expect_json_with(out_buf, length, "\"revocation_epoch\":3,");
	expect_json_with(out_buf, length, "\"result\":0,");
	expect_json_with(out_buf, length, "\"data_class\":2,");
	expect_json_with(out_buf, length, "\"flags\":5,");
	expect_json_with(out_buf, length,
			 "\"attributes\":{\"a_u64\":42,\"b_i64\":-7,"
			 "\"c_bool\":true,\"d_text\":\"x=1|y\\\\z\",\"e_digest\":\"");
	/* The last key of the document is the attributes object. */
	zassert_equal(out_buf[length - 2U], '}');

	/* No attribute -> empty object, still valid. */
	reset_ledger(4U, 1U);
	append_events(0U, 1U, &event);
	zassert_ok(pqcp_sovereign_audit_ocsf_encode_event(
		&event, out_buf, sizeof(out_buf), &length));
	zassert_true(json_valid(out_buf, length));
	expect_json_with(out_buf, length, "\"attributes\":{}}}");

	/* Negative result and large values are encoded losslessly. */
	{
		struct pqcp_sovereign_event_draft draft;
		struct pqcp_sovereign_event raw;

		reset_ledger(4U, 1U);
		fill_draft(&draft, 0U);
		draft.result = INT32_MIN;
		draft.correlation_id = UINT64_MAX;
		zassert_ok(pqcp_sovereign_event_init(&raw, &draft));
		zassert_ok(pqcp_sovereign_event_add_i64(&raw, "m", INT64_MIN, 0U));
		zassert_ok(pqcp_sovereign_event_add_u64(&raw, "n", UINT64_MAX, 0U));
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &raw,
							      &event));
		zassert_ok(pqcp_sovereign_audit_ocsf_encode_event(
			&event, out_buf, sizeof(out_buf), &length));
		zassert_true(json_valid(out_buf, length));
		expect_json_with(out_buf, length, "\"result\":-2147483648,");
		expect_json_with(out_buf, length,
				 "\"correlation_id\":18446744073709551615,");
		expect_json_with(out_buf, length,
				 "\"m\":-9223372036854775808,");
		expect_json_with(out_buf, length,
				 "\"n\":18446744073709551615}");
	}
}

ZTEST(pqcp_sovereign_audit, test_ocsf_json_escaping)
{
	struct pqcp_sovereign_event_draft draft;
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event committed;
	struct pqcp_sovereign_event forged;
	size_t length = 0U;

	fill_draft(&draft, 0U);
	draft.reason = "say \"hi\" \\ done";
	draft.actor = "o\"brien";
	draft.object = "C:\\dir\\file";
	zassert_ok(pqcp_sovereign_event_init(&event, &draft));
	zassert_ok(pqcp_sovereign_event_add_text(&event, "q", "\"\\/", 0U));
	zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
						      &committed));
	zassert_ok(pqcp_sovereign_audit_ocsf_encode_event(
		&committed, out_buf, sizeof(out_buf), &length));
	zassert_true(json_valid(out_buf, length), "%.*s", (int)length,
		     (const char *)out_buf);
	expect_json_with(out_buf, length,
			 "\"message\":\"say \\\"hi\\\" \\\\ done\"");
	expect_json_with(out_buf, length, "\"user_name\":\"o\\\"brien\"");
	expect_json_with(out_buf, length, "\"object\":\"C:\\\\dir\\\\file\"");
	expect_json_with(out_buf, length, "\"q\":\"\\\"\\\\/\"");

	/* Control characters (forged in the struct) become JSON escapes. */
	forged = committed;
	memset(forged.reason, 0, sizeof(forged.reason));
	memcpy(forged.reason, "a\nb\tc\rd\be\ff\x01\x1f", 13U);
	zassert_ok(pqcp_sovereign_audit_ocsf_encode_event(
		&forged, out_buf, sizeof(out_buf), &length));
	zassert_true(json_valid(out_buf, length), "%.*s", (int)length,
		     (const char *)out_buf);
	expect_json_with(out_buf, length,
			 "\"message\":\"a\\nb\\tc\\rd\\be\\ff\\u0001\\u001f\"");
	zassert_equal(count_byte(out_buf, length, '\n'), 0U);
	zassert_equal(count_byte(out_buf, length, '\t'), 0U);
	for (size_t index = 0U; index < length; ++index) {
		zassert_true(out_buf[index] >= 0x20U,
			     "raw control byte at %zu", index);
	}
}

ZTEST(pqcp_sovereign_audit, test_ocsf_class_and_activity_mapping_table)
{
	static const struct {
		unsigned int category;
		unsigned int class_uid;
	} classes[] = {
		{ 0U, 0U },	/* NONE (index 0, unused) */
		{ 6U, 6003U },	/* crypto_operation */
		{ 5U, 5001U },	/* fleet_operation */
		{ 2U, 2004U },	/* security_incident */
		{ 5U, 5007U },	/* deployment */
		{ 6U, 6003U },	/* key_ceremony */
		{ 3U, 3002U },	/* privacy */
		{ 5U, 5008U },	/* recovery */
		{ 5U, 5009U },	/* continuity */
		{ 6U, 6002U },	/* audit_control */
	};
	static const unsigned int activity_ids[] = {
		0U, 1U, 1U, 2U, 3U, 3U, 6U, 3U, 4U, 5U, 5U, 5U, 2U, 5U,
		3U, 7U, 6U, 6U, 2U, 7U, 7U, 4U, 3U, 3U, 3U, 5U, 4U,
	};
	static const struct {
		enum pqcp_sovereign_audit_outcome outcome;
		unsigned int status_id;
	} outcomes[] = {
		{ PQCP_SOVEREIGN_AUDIT_OUTCOME_UNKNOWN, 0U },
		{ PQCP_SOVEREIGN_AUDIT_OUTCOME_SUCCESS, 1U },
		{ PQCP_SOVEREIGN_AUDIT_OUTCOME_FAILURE, 2U },
		{ PQCP_SOVEREIGN_AUDIT_OUTCOME_DENIED, 2U },
		{ PQCP_SOVEREIGN_AUDIT_OUTCOME_PENDING, 3U },
		{ PQCP_SOVEREIGN_AUDIT_OUTCOME_CANCELLED, 4U },
		{ PQCP_SOVEREIGN_AUDIT_OUTCOME_EXPIRED, 5U },
	};
	struct pqcp_sovereign_event_draft draft;
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event committed;
	size_t length = 0U;

	zassert_equal(ARRAY_SIZE(classes),
		      (size_t)PQCP_SOVEREIGN_AUDIT_CLASS_COUNT);
	zassert_equal(ARRAY_SIZE(activity_ids),
		      (size_t)PQCP_SOVEREIGN_AUDIT_ACTIVITY_COUNT);

	for (unsigned int class_index = 1U;
	     class_index < PQCP_SOVEREIGN_AUDIT_CLASS_COUNT; ++class_index) {
		reset_ledger(2U, 1U);
		fill_draft(&draft, 0U);
		draft.event_class =
			(enum pqcp_sovereign_audit_event_class)class_index;
		zassert_ok(pqcp_sovereign_event_init(&event, &draft));
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
							      &committed));
		zassert_ok(pqcp_sovereign_audit_ocsf_encode_event(
			&committed, out_buf, sizeof(out_buf), &length));
		zassert_true(json_valid(out_buf, length));
		snprintf(scratch, sizeof(scratch), "\"category_uid\":%u,"
		         "\"class_uid\":%u,", classes[class_index].category,
		         classes[class_index].class_uid);
		expect_json_with(out_buf, length, scratch);
		snprintf(scratch, sizeof(scratch), "\"type_uid\":%u,",
			 classes[class_index].class_uid * 100U + 3U);
		expect_json_with(out_buf, length, scratch);
	}

	for (unsigned int activity = 1U;
	     activity < PQCP_SOVEREIGN_AUDIT_ACTIVITY_COUNT; ++activity) {
		reset_ledger(2U, 1U);
		fill_draft(&draft, 0U);
		draft.activity = (enum pqcp_sovereign_audit_activity)activity;
		zassert_ok(pqcp_sovereign_event_init(&event, &draft));
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
							      &committed));
		zassert_ok(pqcp_sovereign_audit_ocsf_encode_event(
			&committed, out_buf, sizeof(out_buf), &length));
		zassert_true(json_valid(out_buf, length));
		snprintf(scratch, sizeof(scratch), "\"activity_id\":%u,"
		         "\"activity_name\":\"%s\"", activity_ids[activity],
		         pqcp_sovereign_audit_activity_str(
			         (enum pqcp_sovereign_audit_activity)activity));
		expect_json_with(out_buf, length, scratch);
		snprintf(scratch, sizeof(scratch), "\"type_uid\":%u,",
			 5007U * 100U + activity_ids[activity]);
		expect_json_with(out_buf, length, scratch);
	}

	for (size_t index = 0U; index < ARRAY_SIZE(outcomes); ++index) {
		reset_ledger(2U, 1U);
		fill_draft(&draft, 0U);
		draft.outcome = outcomes[index].outcome;
		zassert_ok(pqcp_sovereign_event_init(&event, &draft));
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
							      &committed));
		zassert_ok(pqcp_sovereign_audit_ocsf_encode_event(
			&committed, out_buf, sizeof(out_buf), &length));
		snprintf(scratch, sizeof(scratch), "\"status_id\":%u,",
			 outcomes[index].status_id);
		expect_json_with(out_buf, length, scratch);
	}

	/* OCSF severity ids follow the enum values 0..5 verbatim. */
	for (unsigned int severity = 0U; severity <= 5U; ++severity) {
		reset_ledger(2U, 1U);
		fill_draft(&draft, 0U);
		draft.severity = (enum pqcp_sovereign_audit_severity)severity;
		zassert_ok(pqcp_sovereign_event_init(&event, &draft));
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &event,
							      &committed));
		zassert_ok(pqcp_sovereign_audit_ocsf_encode_event(
			&committed, out_buf, sizeof(out_buf), &length));
		snprintf(scratch, sizeof(scratch), "\"severity_id\":%u,\"severity\":\"%s\"",
			 severity, pqcp_sovereign_audit_severity_str(
				 (enum pqcp_sovereign_audit_severity)severity));
		expect_json_with(out_buf, length, scratch);
	}
}

ZTEST(pqcp_sovereign_audit, test_ocsf_event_buffer_boundaries_and_negatives)
{
	struct pqcp_sovereign_event event;

	event_encoder_negatives(pqcp_sovereign_audit_ocsf_encode_event);

	reset_ledger(8U, 1U);
	{
		struct pqcp_sovereign_event rich;

		make_event(&rich, 0U);
		add_rich_attributes(&rich);
		zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &rich,
							      &event));
	}
	(void)event_boundaries(pqcp_sovereign_audit_ocsf_encode_event, &event,
			       1U);
}

ZTEST(pqcp_sovereign_audit, test_ocsf_batch_structure_and_negatives)
{
	size_t length = 0U;
	char hex[DIGEST_BYTES * 2U + 1U];

	batch_encoder_negatives(pqcp_sovereign_audit_ocsf_encode_batch);

	reset_ledger(8U, 1U);
	append_events(0U, 3U, NULL);
	build_batch(3U, PQCP_SOVEREIGN_AUDIT_FORMAT_OCSF_JSON);
	zassert_ok(pqcp_sovereign_audit_ocsf_encode_batch(
		&batch, out_buf, sizeof(out_buf), &length));
	zassert_true(json_valid(out_buf, length), "invalid batch JSON");
	{
		static const char expected[] =
			"{\"batch\":{\"schema_version\":1,\"cursor_id\":77,"
			"\"created_at\":2000,\"policy_epoch\":7,"
			"\"first_sequence\":1,\"last_sequence\":3,"
			"\"scanned_through_sequence\":3,\"event_count\":3,"
			"\"tenant_uid\":\"tenant-a\",\"redaction_id\":0,"
			"\"source_anchor_digest\":\"";

		zassert_true(length > sizeof(expected));
		zassert_equal(strncmp((const char *)out_buf, expected,
				      sizeof(expected) - 1U), 0);
	}
	zassert_equal(count_of(out_buf, length, "\"class_uid\":5007,"), 3U,
		      "one OCSF event per batch entry");
	zassert_equal(count_of(out_buf, length, "\"events\":["), 1U);
	hex_encode(batch.batch_digest, DIGEST_BYTES, hex);
	snprintf(scratch, sizeof(scratch), "\"batch_digest\":\"%s\","
	         "\"signature_algorithm_id\":0,\"complete\":true,"
	         "\"resumed\":false},\"events\":[{", hex);
	expect_json_with(out_buf, length, scratch);
	zassert_false(has(out_buf, length, "\"signature\":"));
	zassert_equal(out_buf[length - 2U], ']');
	zassert_equal(out_buf[length - 1U], '}');

	/* Flags and signature. */
	batch.complete = false;
	batch.resumed = true;
	batch.signature_algorithm = PQCP_SOVEREIGN_AUDIT_SIGNATURE_MLDSA;
	batch.signature[0] = 0x01;
	batch.signature[1] = 0xab;
	batch.signature_length = 2U;
	zassert_ok(pqcp_sovereign_audit_ocsf_encode_batch(
		&batch, out_buf, sizeof(out_buf), &length));
	zassert_true(json_valid(out_buf, length));
	expect_json_with(out_buf, length,
			 "\"signature_algorithm_id\":1,\"signature\":\"01ab\","
			 "\"complete\":false,\"resumed\":true}");

	build_batch(2U, PQCP_SOVEREIGN_AUDIT_FORMAT_OCSF_JSON);
	(void)batch_boundaries(pqcp_sovereign_audit_ocsf_encode_batch, &batch,
			       1U);
}

/* ------------------------------------------------------------------ */
/* CBOR                                                                */
/* ------------------------------------------------------------------ */

ZTEST(pqcp_sovereign_audit, test_cbor_event_layout_and_boundaries)
{
	struct pqcp_sovereign_event event;
	struct pqcp_sovereign_event draft_event;
	struct pqcp_sovereign_event_draft draft;
	size_t length = 0U;
	static const uint8_t neg22_key18[] = { 0x12, 0x35 };

	fill_draft(&draft, 0U);
	draft.result = -22;
	zassert_ok(pqcp_sovereign_event_init(&draft_event, &draft));
	add_rich_attributes(&draft_event);
	zassert_ok(pqcp_sovereign_event_ledger_append(&ledger, &draft_event,
						      &event));
	zassert_ok(pqcp_sovereign_audit_cbor_encode_event(
		&event, out_buf, sizeof(out_buf), &length));

	/* Top-level definite map of 31 pairs; keys 1..3 are schema/gen/seq. */
	zassert_equal(out_buf[0], 0xb8U);
	zassert_equal(out_buf[1], 0x1fU);
	zassert_equal(out_buf[2], 0x01U);
	zassert_equal(out_buf[3], 0x01U, "schema_version");
	zassert_equal(out_buf[4], 0x02U);
	zassert_equal(out_buf[5], 0x01U, "generation");
	zassert_equal(out_buf[6], 0x03U);
	zassert_equal(out_buf[7], 0x01U, "sequence");
	zassert_equal(out_buf[8], 0x04U);
	zassert_equal(out_buf[9], 0x19U, "observed_at_ms 1000 needs 2 bytes");
	zassert_equal(out_buf[10], 0x03U);
	zassert_equal(out_buf[11], 0xe8U);
	/* key 18 = result -22 => major type 1, value 21 */
	zassert_true(find_raw(out_buf, length, neg22_key18, sizeof(neg22_key18)) != NULL);
	/* Strings are encoded as CBOR text, digests as byte strings. */
	{
		static const uint8_t src[] = { 0x13, 0x64, 'u', 'n', 'i', 't' };

		zassert_true(find_raw(out_buf, length, src, sizeof(src)) != NULL,
			     "source text (key 19)");
	}
	/* Event digest is a 32-byte bstr under key 30: 0x1e 0x58 0x20. */
	{
		uint8_t needle[3 + DIGEST_BYTES] = { 0x1e, 0x58, 0x20 };

		memcpy(needle + 3, event.event_digest, DIGEST_BYTES);
		zassert_true(find_raw(out_buf, length, needle, sizeof(needle)) !=
			     NULL);
	}

	/* Canonical: re-encoding is byte-identical; sweep capacities. */
	(void)event_boundaries(pqcp_sovereign_audit_cbor_encode_event, &event,
			       1U);

	/* Negatives */
	event_encoder_negatives(pqcp_sovereign_audit_cbor_encode_event);
}

ZTEST(pqcp_sovereign_audit, test_cbor_batch_validation_and_boundaries)
{
	struct pqcp_sovereign_export_batch bad;
	size_t length = 0U;

	reset_ledger(8U, 1U);
	append_events(0U, 2U, NULL);
	build_batch(2U, PQCP_SOVEREIGN_AUDIT_FORMAT_CBOR);
	zassert_ok(pqcp_sovereign_audit_cbor_encode_batch(
		&batch, out_buf, sizeof(out_buf), &length));
	/* map(19) fits in the initial byte: 0xa0 | 19; key1 = schema version */
	zassert_equal(out_buf[0], 0xb3U);
	zassert_equal(out_buf[1], 0x01U);
	zassert_equal(out_buf[2], 0x01U);
	zassert_equal(out_buf[3], 0x02U);
	zassert_equal(out_buf[4], 0x18U);
	zassert_equal(out_buf[5], 77U, "cursor id");
	(void)batch_boundaries(pqcp_sovereign_audit_cbor_encode_batch, &batch,
			       1U);

	batch_encoder_negatives(pqcp_sovereign_audit_cbor_encode_batch);
	/* batch_encoder_negatives rebuilt the batch as CEF; rebuild. */
	build_batch(2U, PQCP_SOVEREIGN_AUDIT_FORMAT_CBOR);

#define EXPECT_BATCH_REJECTED(...)                                        \
	do {                                                                   \
		bad = batch;                                                   \
		__VA_ARGS__;                                                  \
		zassert_equal(pqcp_sovereign_audit_cbor_encode_batch(          \
				      &bad, out_buf, sizeof(out_buf), &length),\
			      -EINVAL, "not rejected: " #__VA_ARGS__);          \
	} while (0)
	EXPECT_BATCH_REJECTED(bad.cursor_id = 0U);
	EXPECT_BATCH_REJECTED(bad.created_at_ms = 0U);
	EXPECT_BATCH_REJECTED(bad.first_sequence = 0U);
	EXPECT_BATCH_REJECTED(bad.last_sequence = bad.first_sequence - 1U);
	EXPECT_BATCH_REJECTED(bad.scanned_through_sequence =
				      bad.last_sequence - 1U);
	EXPECT_BATCH_REJECTED(bad.signature_algorithm =
				      PQCP_SOVEREIGN_AUDIT_SIGNATURE_NONE,
			      bad.signature_length = 8U);
	EXPECT_BATCH_REJECTED(bad.signature_algorithm =
				      PQCP_SOVEREIGN_AUDIT_SIGNATURE_MLDSA,
			      bad.signature_length = 0U);

	/* An event that fails validation poisons the whole batch encode. */
	memset(&batch_events[1], 0, sizeof(batch_events[1]));
	zassert_equal(pqcp_sovereign_audit_cbor_encode_batch(
			      &batch, out_buf, sizeof(out_buf), &length),
		      -EINVAL);
	zassert_equal(length, 0U);
}

ZTEST(pqcp_sovereign_audit, test_batch_with_maximum_signature_fits_all_encoders)
{
	size_t length = 0U;

	reset_ledger(8U, 1U);
	append_events(0U, 2U, NULL);
	build_batch(2U, PQCP_SOVEREIGN_AUDIT_FORMAT_CBOR);
	batch.signature_algorithm = PQCP_SOVEREIGN_AUDIT_SIGNATURE_MLDSA;
	batch.signature_length = sizeof(batch.signature);
	for (size_t index = 0U; index < sizeof(batch.signature); ++index) {
		batch.signature[index] = (uint8_t)(index * 31U + 7U);
	}

	zassert_ok(pqcp_sovereign_audit_cbor_encode_batch(
		&batch, out_buf, sizeof(out_buf), &length));
	zassert_true(length > sizeof(batch.signature));
	{
		size_t exact = length;

		memset(guard_buf, GUARD_FILL, sizeof(guard_buf));
		zassert_equal(pqcp_sovereign_audit_cbor_encode_batch(
				      &batch, guard_buf, exact - 1U, &length),
			      -ENOSPC);
		zassert_equal(guard_buf[exact - 1U], GUARD_FILL);
	}

	zassert_ok(pqcp_sovereign_audit_ocsf_encode_batch(
		&batch, out_buf, sizeof(out_buf), &length));
	zassert_true(json_valid(out_buf, length));
	{
		size_t exact = length;

		memset(guard_buf, GUARD_FILL, sizeof(guard_buf));
		zassert_equal(pqcp_sovereign_audit_ocsf_encode_batch(
				      &batch, guard_buf, exact - 1U, &length),
			      -ENOSPC);
		zassert_equal(guard_buf[exact - 1U], GUARD_FILL);
	}

	zassert_ok(pqcp_sovereign_audit_cef_encode_batch(
		&batch, out_buf, sizeof(out_buf), &length));
	zassert_true(length > 2U * sizeof(batch.signature));
	{
		size_t exact = length;

		memset(guard_buf, GUARD_FILL, sizeof(guard_buf));
		zassert_equal(pqcp_sovereign_audit_cef_encode_batch(
				      &batch, guard_buf, exact - 1U, &length),
			      -ENOSPC);
		zassert_equal(guard_buf[exact - 1U], GUARD_FILL);
	}
}

/* ------------------------------------------------------------------ */
/* Redaction through the exporters                                     */
/* ------------------------------------------------------------------ */

ZTEST(pqcp_sovereign_audit, test_redaction_is_effective_in_all_exporters)
{
	struct pqcp_sovereign_event source;
	struct pqcp_sovereign_event proj;
	encode_event_fn encoders[] = {
		pqcp_sovereign_audit_cbor_encode_event,
		pqcp_sovereign_audit_cef_encode_event,
		pqcp_sovereign_audit_ocsf_encode_event,
	};
	size_t length = 0U;

	make_privacy_event(&source, "tenant-a");

	for (size_t index = 0U; index < ARRAY_SIZE(encoders); ++index) {
		/* Control: the unredacted export carries the cleartext. */
		zassert_ok(encoders[index](&source, out_buf, sizeof(out_buf),
					   &length));
		zassert_true(has(out_buf, length, "alice"));
		zassert_true(has(out_buf, length, "bob@example.com"));
		zassert_true(has(out_buf, length, "because"));

		/* Pseudonymize: no cleartext identity, personal value or key
		 * material survives; pseudonym prefix is visible.
		 */
		zassert_ok(pqcp_sovereign_event_redact(
			&source, PQCP_SOVEREIGN_AUDIT_REDACTION_PSEUDONYMIZE, true,
			true, &proj));
		zassert_ok(encoders[index](&proj, out_buf, sizeof(out_buf),
					   &length));
		zassert_false(has(out_buf, length, "alice"));
		zassert_false(has(out_buf, length, "key/1"));
		zassert_false(has(out_buf, length, "bob@example.com"));
		zassert_true(has(out_buf, length, "h:"));
		zassert_true(has(out_buf, length, "public-note"));

		/* Minimize. */
		zassert_ok(pqcp_sovereign_event_redact(
			&source, PQCP_SOVEREIGN_AUDIT_REDACTION_MINIMIZE, true,
			true, &proj));
		zassert_ok(encoders[index](&proj, out_buf, sizeof(out_buf),
					   &length));
		zassert_false(has(out_buf, length, "alice"));
		zassert_false(has(out_buf, length, "because"));
		zassert_false(has(out_buf, length, "bob@example.com"));
		zassert_false(has(out_buf, length, "s3cr3t-value"));
		zassert_true(has(out_buf, length, "key/1"));

		/* Strict. */
		zassert_ok(pqcp_sovereign_event_redact(
			&source, PQCP_SOVEREIGN_AUDIT_REDACTION_STRICT, true,
			true, &proj));
		zassert_ok(encoders[index](&proj, out_buf, sizeof(out_buf),
					   &length));
		zassert_false(has(out_buf, length, "alice"));
		zassert_false(has(out_buf, length, "key/1"));
		zassert_false(has(out_buf, length, "because"));
		zassert_false(has(out_buf, length, "unit"));
		zassert_false(has(out_buf, length, "bob@example.com"));
		zassert_false(has(out_buf, length, "s3cr3t-value"));
		zassert_false(has(out_buf, length, "public-note"));
		zassert_true(has(out_buf, length, "redacted"));
	}
}
