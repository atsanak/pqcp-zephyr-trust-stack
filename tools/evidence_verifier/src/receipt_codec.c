/*
 * SPDX-License-Identifier: MIT
 *
 * Deterministic-CBOR codec for appraisal statements, checkpoints, receipts
 * and consistency files (see receipt_codec.h).
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/fleet_cose.h>

#include "receipt_codec.h"

/* ------------------------------------------------------------------ */
/* Writer helpers                                                       */
/* ------------------------------------------------------------------ */

typedef struct pqcp_fleet_cbor_writer writer_t;
typedef struct pqcp_fleet_cbor_reader reader_t;

static void w_key(writer_t *w, uint64_t key)
{
	(void)pqcp_fleet_cbor_write_uint(w, key);
}

static void w_uint(writer_t *w, uint64_t key, uint64_t value)
{
	w_key(w, key);
	(void)pqcp_fleet_cbor_write_uint(w, value);
}

static void w_bytes(writer_t *w, uint64_t key, const uint8_t *value,
		    size_t length)
{
	w_key(w, key);
	(void)pqcp_fleet_cbor_write_bytes(w, value, length);
}

static void w_text(writer_t *w, uint64_t key, const char *value)
{
	w_key(w, key);
	(void)pqcp_fleet_cbor_write_text(w, value, strlen(value));
}

static void w_nodes(writer_t *w, uint64_t key, const uint8_t (*nodes)[32],
		    size_t count)
{
	w_key(w, key);
	(void)pqcp_fleet_cbor_write_array(w, count);
	for (size_t i = 0U; i < count; ++i) {
		(void)pqcp_fleet_cbor_write_bytes(w, nodes[i], 32U);
	}
}

static int w_finish(writer_t *w, size_t *length)
{
	int ret = pqcp_fleet_cbor_writer_finish(w, length);

	if (ret == PQCP_FLEET_COSE_ERR_CAPACITY) {
		return -ENOSPC;
	}
	return ret == 0 ? 0 : -EINVAL;
}

/* ------------------------------------------------------------------ */
/* Reader helpers                                                       */
/* ------------------------------------------------------------------ */

static int r_map(reader_t *r, size_t expected_entries,
		 struct pqcp_fleet_cbor_map_cursor *cursor)
{
	if (pqcp_fleet_cbor_read_map(r, cursor) != 0 ||
	    cursor->remaining != expected_entries) {
		return -EBADMSG;
	}
	return 0;
}

static int r_key(reader_t *r, struct pqcp_fleet_cbor_map_cursor *cursor,
		 int64_t expected)
{
	struct pqcp_fleet_cbor_map_key key;

	if (pqcp_fleet_cbor_map_next(r, cursor, &key) != 0 || !key.integer ||
	    key.integer_value != expected) {
		return -EBADMSG;
	}
	return 0;
}

static int r_uint(reader_t *r, uint64_t *value)
{
	return pqcp_fleet_cbor_read_uint(r, value) == 0 ? 0 : -EBADMSG;
}

static int r_fixed(reader_t *r, uint8_t *out, size_t length)
{
	struct pqcp_fleet_cbor_slice slice;

	if (pqcp_fleet_cbor_read_bytes(r, &slice) != 0 ||
	    slice.length != length) {
		return -EBADMSG;
	}
	memcpy(out, slice.data, length);
	return 0;
}

static int r_nodes(reader_t *r, uint8_t (*nodes)[32], size_t *count)
{
	size_t n;

	if (pqcp_fleet_cbor_read_array(r, &n) != 0 || n > RC_MAX_PATH_NODES) {
		return -EBADMSG;
	}
	for (size_t i = 0U; i < n; ++i) {
		if (r_fixed(r, nodes[i], 32U) != 0) {
			return -EBADMSG;
		}
	}
	*count = n;
	return 0;
}

static bool hex_valid_or_empty(const char *s)
{
	size_t n = strlen(s);

	if (n == 0U) {
		return true;
	}
	if (n != RC_HEX_CHARS) {
		return false;
	}
	for (size_t i = 0U; i < n; ++i) {
		if (!((s[i] >= '0' && s[i] <= '9') ||
		      (s[i] >= 'a' && s[i] <= 'f'))) {
			return false;
		}
	}
	return true;
}

static int r_hex_text(reader_t *r, char out[RC_HEX_CHARS + 1U])
{
	struct pqcp_fleet_cbor_slice slice;

	if (pqcp_fleet_cbor_read_text(r, &slice) != 0 ||
	    slice.length > RC_HEX_CHARS) {
		return -EBADMSG;
	}
	memcpy(out, slice.data, slice.length);
	out[slice.length] = '\0';
	return hex_valid_or_empty(out) ? 0 : -EBADMSG;
}

/* ------------------------------------------------------------------ */
/* Statement                                                            */
/* ------------------------------------------------------------------ */

static bool verdict_valid(const char *verdict)
{
	return strcmp(verdict, RC_VERDICT_OK) == 0 ||
	       strcmp(verdict, RC_VERDICT_REJECT) == 0;
}

int rc_statement_encode(const struct rc_statement *s, uint8_t *out,
			size_t capacity, size_t *length)
{
	writer_t w;

	if (s == NULL || out == NULL || length == NULL ||
	    !hex_valid_or_empty(s->passport_digest_hex) ||
	    !hex_valid_or_empty(s->trail_head_hex) ||
	    !verdict_valid(s->verdict)) {
		return -EINVAL;
	}
	pqcp_fleet_cbor_writer_init(&w, out, capacity);
	(void)pqcp_fleet_cbor_write_map(&w, 8U);
	w_text(&w, 1U, RC_STATEMENT_TAG);
	w_text(&w, 2U, s->passport_digest_hex);
	if (s->has_device_pk_hash) {
		w_bytes(&w, 3U, s->device_pk_hash, 32U);
	} else {
		w_key(&w, 3U);
		(void)pqcp_fleet_cbor_write_null(&w);
	}
	w_text(&w, 4U, s->trail_head_hex);
	w_text(&w, 5U, s->verdict);
	w_bytes(&w, 6U, s->verifier_sha256, 32U);
	w_key(&w, 7U);
	(void)pqcp_fleet_cbor_write_bool(&w, s->signature_verified);
	w_bytes(&w, 8U, s->transcript_sha256, 32U);
	return w_finish(&w, length);
}

static int statement_read(reader_t *r, struct rc_statement *s)
{
	struct pqcp_fleet_cbor_map_cursor cursor;
	struct pqcp_fleet_cbor_slice text;

	memset(s, 0, sizeof(*s));
	if (r_map(r, 8U, &cursor) != 0) {
		return -EBADMSG;
	}
	if (r_key(r, &cursor, 1) != 0 ||
	    pqcp_fleet_cbor_read_text(r, &text) != 0 ||
	    text.length != strlen(RC_STATEMENT_TAG) ||
	    memcmp(text.data, RC_STATEMENT_TAG, text.length) != 0) {
		return -EBADMSG;
	}
	if (r_key(r, &cursor, 2) != 0 ||
	    r_hex_text(r, s->passport_digest_hex) != 0) {
		return -EBADMSG;
	}
	if (r_key(r, &cursor, 3) != 0 || r->offset >= r->length) {
		return -EBADMSG;
	}
	if (r->buffer[r->offset] == 0xf6U) {
		if (pqcp_fleet_cbor_read_null(r) != 0) {
			return -EBADMSG;
		}
	} else {
		if (r_fixed(r, s->device_pk_hash, 32U) != 0) {
			return -EBADMSG;
		}
		s->has_device_pk_hash = true;
	}
	if (r_key(r, &cursor, 4) != 0 ||
	    r_hex_text(r, s->trail_head_hex) != 0) {
		return -EBADMSG;
	}
	if (r_key(r, &cursor, 5) != 0 ||
	    pqcp_fleet_cbor_read_text(r, &text) != 0 ||
	    text.length >= sizeof(s->verdict)) {
		return -EBADMSG;
	}
	memcpy(s->verdict, text.data, text.length);
	s->verdict[text.length] = '\0';
	if (!verdict_valid(s->verdict)) {
		return -EBADMSG;
	}
	if (r_key(r, &cursor, 6) != 0 ||
	    r_fixed(r, s->verifier_sha256, 32U) != 0) {
		return -EBADMSG;
	}
	if (r_key(r, &cursor, 7) != 0 ||
	    pqcp_fleet_cbor_read_bool(r, &s->signature_verified) != 0) {
		return -EBADMSG;
	}
	if (r_key(r, &cursor, 8) != 0 ||
	    r_fixed(r, s->transcript_sha256, 32U) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int rc_statement_decode(const uint8_t *in, size_t length,
			struct rc_statement *statement)
{
	reader_t r;

	if (in == NULL || statement == NULL) {
		return -EINVAL;
	}
	pqcp_fleet_cbor_reader_init(&r, in, length);
	if (statement_read(&r, statement) != 0 ||
	    pqcp_fleet_cbor_reader_finish(&r) != 0) {
		memset(statement, 0, sizeof(*statement));
		return -EBADMSG;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Checkpoint                                                           */
/* ------------------------------------------------------------------ */

static void checkpoint_write(writer_t *w, const struct rc_checkpoint *c)
{
	(void)pqcp_fleet_cbor_write_map(w, 9U);
	w_uint(w, 1U, c->schema_version);
	w_uint(w, 2U, c->tree_size);
	w_uint(w, 3U, c->timestamp_ms);
	w_uint(w, 4U, c->sequence);
	w_bytes(w, 5U, c->log_id, 32U);
	w_bytes(w, 6U, c->root, 32U);
	w_bytes(w, 7U, c->signer_key_id, 32U);
	w_bytes(w, 8U, c->transcript_digest, 32U);
	w_bytes(w, 9U, c->signature, RC_SIGNATURE_BYTES);
}

static int checkpoint_read(reader_t *r, struct rc_checkpoint *c)
{
	struct pqcp_fleet_cbor_map_cursor cursor;
	uint64_t schema;

	memset(c, 0, sizeof(*c));
	if (r_map(r, 9U, &cursor) != 0) {
		return -EBADMSG;
	}
	if (r_key(r, &cursor, 1) != 0 || r_uint(r, &schema) != 0 ||
	    schema != PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION) {
		return -EBADMSG;
	}
	c->schema_version = (uint32_t)schema;
	if (r_key(r, &cursor, 2) != 0 || r_uint(r, &c->tree_size) != 0 ||
	    r_key(r, &cursor, 3) != 0 || r_uint(r, &c->timestamp_ms) != 0 ||
	    r_key(r, &cursor, 4) != 0 || r_uint(r, &c->sequence) != 0 ||
	    r_key(r, &cursor, 5) != 0 || r_fixed(r, c->log_id, 32U) != 0 ||
	    r_key(r, &cursor, 6) != 0 || r_fixed(r, c->root, 32U) != 0 ||
	    r_key(r, &cursor, 7) != 0 ||
	    r_fixed(r, c->signer_key_id, 32U) != 0 ||
	    r_key(r, &cursor, 8) != 0 ||
	    r_fixed(r, c->transcript_digest, 32U) != 0 ||
	    r_key(r, &cursor, 9) != 0 ||
	    r_fixed(r, c->signature, RC_SIGNATURE_BYTES) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int rc_checkpoint_encode(const struct rc_checkpoint *c, uint8_t *out,
			 size_t capacity, size_t *length)
{
	writer_t w;

	if (c == NULL || out == NULL || length == NULL) {
		return -EINVAL;
	}
	pqcp_fleet_cbor_writer_init(&w, out, capacity);
	checkpoint_write(&w, c);
	return w_finish(&w, length);
}

int rc_checkpoint_decode(const uint8_t *in, size_t length,
			 struct rc_checkpoint *c)
{
	reader_t r;

	if (in == NULL || c == NULL) {
		return -EINVAL;
	}
	pqcp_fleet_cbor_reader_init(&r, in, length);
	if (checkpoint_read(&r, c) != 0 ||
	    pqcp_fleet_cbor_reader_finish(&r) != 0) {
		memset(c, 0, sizeof(*c));
		return -EBADMSG;
	}
	return 0;
}

void rc_checkpoint_to_fleet(
	struct rc_checkpoint *c,
	struct pqcp_fleet_transparency_checkpoint *fleet)
{
	memset(fleet, 0, sizeof(*fleet));
	fleet->schema_version = c->schema_version;
	fleet->tree_size = c->tree_size;
	fleet->timestamp_ms = c->timestamp_ms;
	fleet->sequence = c->sequence;
	memcpy(fleet->log_id, c->log_id, 32U);
	memcpy(fleet->root, c->root, 32U);
	memcpy(fleet->signer_key_id, c->signer_key_id, 32U);
	memcpy(fleet->transcript_digest, c->transcript_digest, 32U);
	fleet->signature = c->signature;
	fleet->signature_capacity = sizeof(c->signature);
	fleet->signature_length = sizeof(c->signature);
}

int rc_checkpoint_from_fleet(
	const struct pqcp_fleet_transparency_checkpoint *fleet,
	struct rc_checkpoint *c)
{
	if (fleet == NULL || c == NULL || fleet->signature == NULL ||
	    fleet->signature_length != RC_SIGNATURE_BYTES) {
		return -EINVAL;
	}
	memset(c, 0, sizeof(*c));
	c->schema_version = fleet->schema_version;
	c->tree_size = fleet->tree_size;
	c->timestamp_ms = fleet->timestamp_ms;
	c->sequence = fleet->sequence;
	memcpy(c->log_id, fleet->log_id, 32U);
	memcpy(c->root, fleet->root, 32U);
	memcpy(c->signer_key_id, fleet->signer_key_id, 32U);
	memcpy(c->transcript_digest, fleet->transcript_digest, 32U);
	memcpy(c->signature, fleet->signature, RC_SIGNATURE_BYTES);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Receipt                                                              */
/* ------------------------------------------------------------------ */

int rc_receipt_encode(const struct rc_receipt *rc, uint8_t *out,
		      size_t capacity, size_t *length)
{
	writer_t w;

	if (rc == NULL || out == NULL || length == NULL ||
	    rc->statement_length > RC_MAX_STATEMENT_BYTES ||
	    rc->path_count > RC_MAX_PATH_NODES) {
		return -EINVAL;
	}
	pqcp_fleet_cbor_writer_init(&w, out, capacity);
	(void)pqcp_fleet_cbor_write_map(&w, 5U);
	w_bytes(&w, 1U, rc->statement, rc->statement_length);
	w_uint(&w, 2U, rc->leaf_index);
	w_uint(&w, 3U, rc->tree_size);
	w_nodes(&w, 4U, (const uint8_t (*)[32])rc->path, rc->path_count);
	w_key(&w, 5U);
	checkpoint_write(&w, &rc->checkpoint);
	return w_finish(&w, length);
}

int rc_receipt_decode(const uint8_t *in, size_t length, struct rc_receipt *rc)
{
	struct pqcp_fleet_cbor_map_cursor cursor;
	struct pqcp_fleet_cbor_slice statement;
	reader_t r;

	if (in == NULL || rc == NULL) {
		return -EINVAL;
	}
	memset(rc, 0, sizeof(*rc));
	pqcp_fleet_cbor_reader_init(&r, in, length);
	if (r_map(&r, 5U, &cursor) != 0 || r_key(&r, &cursor, 1) != 0 ||
	    pqcp_fleet_cbor_read_bytes(&r, &statement) != 0 ||
	    statement.length > RC_MAX_STATEMENT_BYTES) {
		goto bad;
	}
	memcpy(rc->statement, statement.data, statement.length);
	rc->statement_length = statement.length;
	if (r_key(&r, &cursor, 2) != 0 || r_uint(&r, &rc->leaf_index) != 0 ||
	    r_key(&r, &cursor, 3) != 0 || r_uint(&r, &rc->tree_size) != 0 ||
	    r_key(&r, &cursor, 4) != 0 ||
	    r_nodes(&r, rc->path, &rc->path_count) != 0 ||
	    r_key(&r, &cursor, 5) != 0 ||
	    checkpoint_read(&r, &rc->checkpoint) != 0 ||
	    pqcp_fleet_cbor_reader_finish(&r) != 0) {
		goto bad;
	}
	return 0;
bad:
	memset(rc, 0, sizeof(*rc));
	return -EBADMSG;
}

/* ------------------------------------------------------------------ */
/* Consistency file                                                     */
/* ------------------------------------------------------------------ */

int rc_consistency_encode(const struct rc_consistency *c, uint8_t *out,
			  size_t capacity, size_t *length)
{
	writer_t w;

	if (c == NULL || out == NULL || length == NULL ||
	    c->node_count > RC_MAX_PATH_NODES) {
		return -EINVAL;
	}
	pqcp_fleet_cbor_writer_init(&w, out, capacity);
	(void)pqcp_fleet_cbor_write_map(&w, 5U);
	w_uint(&w, 1U, c->old_size);
	w_uint(&w, 2U, c->new_size);
	w_nodes(&w, 3U, (const uint8_t (*)[32])c->nodes, c->node_count);
	w_key(&w, 4U);
	checkpoint_write(&w, &c->old_checkpoint);
	w_key(&w, 5U);
	checkpoint_write(&w, &c->new_checkpoint);
	return w_finish(&w, length);
}

int rc_consistency_decode(const uint8_t *in, size_t length,
			  struct rc_consistency *c)
{
	struct pqcp_fleet_cbor_map_cursor cursor;
	reader_t r;

	if (in == NULL || c == NULL) {
		return -EINVAL;
	}
	memset(c, 0, sizeof(*c));
	pqcp_fleet_cbor_reader_init(&r, in, length);
	if (r_map(&r, 5U, &cursor) != 0 || r_key(&r, &cursor, 1) != 0 ||
	    r_uint(&r, &c->old_size) != 0 || r_key(&r, &cursor, 2) != 0 ||
	    r_uint(&r, &c->new_size) != 0 || r_key(&r, &cursor, 3) != 0 ||
	    r_nodes(&r, c->nodes, &c->node_count) != 0 ||
	    r_key(&r, &cursor, 4) != 0 ||
	    checkpoint_read(&r, &c->old_checkpoint) != 0 ||
	    r_key(&r, &cursor, 5) != 0 ||
	    checkpoint_read(&r, &c->new_checkpoint) != 0 ||
	    pqcp_fleet_cbor_reader_finish(&r) != 0) {
		memset(c, 0, sizeof(*c));
		return -EBADMSG;
	}
	return 0;
}
