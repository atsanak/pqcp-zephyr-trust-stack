/* SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/runtime_key_store.h>

#include "runtime_internal.h"
#include "sovereign_audit_internal.h"

#define DIGEST_BYTES PQCP_SOVEREIGN_AUDIT_DIGEST_BYTES
#define SCHEMA PQCP_SOVEREIGN_AUDIT_SCHEMA_VERSION

static bool policy_valid(const struct pqcp_sovereign_audit_export_policy *p)
{
	return p != NULL && p->policy_epoch != 0U && p->maximum_events != 0U &&
	       pqcp_sovereign_audit_internal_text_valid(
		       p->tenant_id, sizeof(p->tenant_id), false) &&
	       pqcp_sovereign_audit_internal_text_valid(
		       p->realm, sizeof(p->realm), true) &&
	       (unsigned int)p->minimum_severity <= PQCP_SOVEREIGN_AUDIT_SEVERITY_CRITICAL &&
	       (unsigned int)p->maximum_data_class < PQCP_SOVEREIGN_AUDIT_DATA_CLASS_COUNT &&
	       (unsigned int)p->redaction <= PQCP_SOVEREIGN_AUDIT_REDACTION_STRICT &&
	       (unsigned int)p->format <= PQCP_SOVEREIGN_AUDIT_FORMAT_OCSF_JSON &&
	       !(p->required_flags & p->forbidden_flags) &&
	       !((p->required_flags | p->forbidden_flags) & ~0xffU) &&
	       !(p->class_mask & ~((1ULL << PQCP_SOVEREIGN_AUDIT_CLASS_COUNT) - 2U)) &&
	       !(p->activity_mask & ~((1ULL << PQCP_SOVEREIGN_AUDIT_ACTIVITY_COUNT) - 2U));
}

bool pqcp_sovereign_audit_internal_policy_matches(
	const struct pqcp_sovereign_audit_export_policy *p,
	const struct pqcp_sovereign_event *e)
{
	return policy_valid(p) && e != NULL &&
	       (unsigned int)e->event_class < PQCP_SOVEREIGN_AUDIT_CLASS_COUNT &&
	       (unsigned int)e->activity < PQCP_SOVEREIGN_AUDIT_ACTIVITY_COUNT &&
	       pqcp_sovereign_audit_internal_text_valid(
		       e->tenant.tenant_id, sizeof(e->tenant.tenant_id), false) &&
	       pqcp_sovereign_audit_internal_text_valid(
		       e->tenant.realm, sizeof(e->tenant.realm), true) &&
	       strcmp(p->tenant_id, e->tenant.tenant_id) == 0 &&
	       (p->realm[0] == '\0' || strcmp(p->realm, e->tenant.realm) == 0) &&
	       (!p->class_mask || (p->class_mask & (1ULL << e->event_class))) &&
	       (!p->activity_mask || (p->activity_mask & (1ULL << e->activity))) &&
	       (e->flags & p->required_flags) == p->required_flags &&
	       !(e->flags & p->forbidden_flags) && e->severity >= p->minimum_severity &&
	       e->data_class <= p->maximum_data_class;
}

static bool same_policy(const struct pqcp_sovereign_audit_export_policy *a,
			const struct pqcp_sovereign_audit_export_policy *b)
{
	/* Compare fields, never structure padding. */
	return strcmp(a->tenant_id, b->tenant_id) == 0 && strcmp(a->realm, b->realm) == 0 &&
	       a->class_mask == b->class_mask && a->activity_mask == b->activity_mask &&
	       a->required_flags == b->required_flags && a->forbidden_flags == b->forbidden_flags &&
	       a->minimum_severity == b->minimum_severity && a->maximum_data_class == b->maximum_data_class &&
	       a->redaction == b->redaction && a->format == b->format &&
	       a->maximum_events == b->maximum_events && a->policy_epoch == b->policy_epoch &&
	       a->require_signature == b->require_signature &&
	       a->include_attributes == b->include_attributes && a->include_reasons == b->include_reasons;
}

static int exporter_lock(struct pqcp_sovereign_audit_exporter *x)
{
	if (x == NULL || !x->initialized || x->schema_version != SCHEMA) {
		return -EINVAL;
	}
	return k_mutex_lock(&x->lock, K_FOREVER);
}

static struct pqcp_sovereign_audit_cursor *find_cursor(
	struct pqcp_sovereign_audit_exporter *x, uint64_t id)
{
	for (size_t i = 0U; i < x->storage.cursor_capacity; ++i) {
		if (x->storage.cursors[i].occupied && x->storage.cursors[i].cursor_id == id) {
			return &x->storage.cursors[i];
		}
	}
	return NULL;
}

static int cursor_live(const struct pqcp_sovereign_audit_cursor *c, uint64_t now)
{
	if (c == NULL) {
		return -ENOENT;
	}
	if (now < c->opened_at_ms) {
		return -EINVAL;
	}
	return now >= c->expires_at_ms ? -ETIMEDOUT : 0;
}

static void release_pending(struct pqcp_sovereign_audit_exporter *x)
{
	pqcp_runtime_secure_zero(x->storage.workspace_events,
		x->storage.workspace_event_capacity * sizeof(*x->storage.workspace_events));
	pqcp_runtime_secure_zero(&x->pending_batch, sizeof(x->pending_batch));
	pqcp_runtime_secure_zero(&x->pending_policy, sizeof(x->pending_policy));
	pqcp_runtime_secure_zero(x->pending_snapshot_digest, sizeof(x->pending_snapshot_digest));
}

int pqcp_sovereign_audit_exporter_init(
	struct pqcp_sovereign_audit_exporter *x,
	struct pqcp_sovereign_event_ledger *ledger,
	const struct pqcp_sovereign_audit_export_config *config,
	const struct pqcp_sovereign_audit_export_storage *storage)
{
	if (x == NULL || ledger == NULL || !ledger->initialized || config == NULL || storage == NULL ||
	    config->maximum_cursor_lifetime_ms == 0U || config->maximum_batch_events == 0U ||
	    storage->cursors == NULL || storage->cursor_capacity == 0U ||
	    storage->cursor_capacity > SIZE_MAX / sizeof(*storage->cursors) ||
	    storage->workspace_events == NULL || storage->workspace_event_capacity == 0U ||
	    storage->workspace_event_capacity > SIZE_MAX / sizeof(*storage->workspace_events) ||
	    config->maximum_batch_events > storage->workspace_event_capacity ||
	    (config->signature_required && !config->signing_enabled) ||
	    (config->signing_enabled && (config->key_store == NULL ||
		pqcp_runtime_key_store_validate(config->key_store) != 0 ||
		!pqcp_runtime_key_handle_is_valid(&config->signing_key) ||
		config->signing_key.family != PQCP_RUNTIME_KEY_MLDSA_KEYPAIR))) {
		return -EINVAL;
	}
	if (pqcp_sovereign_event_ledger_verify(ledger) != 0) {
		return -EBADMSG;
	}
	memset(x, 0, sizeof(*x));
	x->schema_version = SCHEMA;
	x->ledger = ledger;
	x->config = *config;
	x->storage = *storage;
	x->next_cursor_id = 1U;
	x->next_generation = 1U;
	memset(storage->cursors, 0, storage->cursor_capacity * sizeof(*storage->cursors));
	release_pending(x);
	k_mutex_init(&x->lock);
	x->initialized = true;
	return 0;
}

int pqcp_sovereign_audit_export_open(
	struct pqcp_sovereign_audit_exporter *x, const char *consumer, const char *tenant,
	uint64_t first, uint64_t now, uint64_t expires, uint64_t epoch, uint64_t *id)
{
	struct pqcp_sovereign_audit_cursor *free_cursor = NULL;
	uint64_t oldest, last;
	int ret;

	if (id == NULL || now == 0U || expires <= now || epoch == 0U ||
	    !pqcp_sovereign_audit_internal_text_valid(consumer, PQCP_SOVEREIGN_AUDIT_ACTOR_MAX_CHARS, false) ||
	    !pqcp_sovereign_audit_internal_text_valid(tenant, PQCP_SOVEREIGN_AUDIT_TENANT_MAX_CHARS, false)) {
		return -EINVAL;
	}
	*id = 0U;
	ret = exporter_lock(x);
	if (ret != 0) {
		return ret;
	}
	if (expires - now > x->config.maximum_cursor_lifetime_ms) {
		ret = -ERANGE;
		goto out;
	}
	if (x->next_cursor_id == 0U || x->next_cursor_id == UINT64_MAX ||
	    x->next_generation == 0U || x->next_generation == UINT32_MAX) {
		ret = -EOVERFLOW;
		goto out;
	}
	ret = pqcp_sovereign_event_ledger_bounds(x->ledger, &oldest, &last);
	if (ret != 0) {
		goto out;
	}
	first = first == 0U ? oldest : first;
	if (first < oldest || (last != 0U && first > last + 1U) || (last == 0U && first > oldest)) {
		ret = first < oldest ? -ESTALE : -ERANGE;
		goto out;
	}
	for (size_t i = 0U; i < x->storage.cursor_capacity; ++i) {
		if (!x->storage.cursors[i].occupied) {
			free_cursor = &x->storage.cursors[i];
			break;
		}
	}
	if (free_cursor == NULL) {
		ret = -ENOSPC;
		goto out;
	}
	memset(free_cursor, 0, sizeof(*free_cursor));
	free_cursor->schema_version = SCHEMA;
	free_cursor->generation = x->next_generation++;
	free_cursor->cursor_id = x->next_cursor_id++;
	memcpy(free_cursor->consumer_id, consumer, strlen(consumer));
	memcpy(free_cursor->tenant_id, tenant, strlen(tenant));
	free_cursor->next_sequence = first;
	free_cursor->acknowledged_sequence = first - 1U;
	free_cursor->opened_at_ms = now;
	free_cursor->expires_at_ms = expires;
	free_cursor->policy_epoch = epoch;
	free_cursor->state = PQCP_SOVEREIGN_AUDIT_CURSOR_ACTIVE;
	free_cursor->occupied = true;
	*id = free_cursor->cursor_id;
out:
	(void)k_mutex_unlock(&x->lock);
	return ret;
}

/* The exporter lock is held, then the ledger lock: never the reverse. */
static int collect_batch(struct pqcp_sovereign_audit_exporter *x,
	const struct pqcp_sovereign_audit_cursor *c,
	const struct pqcp_sovereign_audit_export_policy *p, uint64_t now)
{
	struct pqcp_sovereign_export_batch *b = &x->pending_batch;
	struct pqcp_sovereign_event_ledger *l = x->ledger;
	const uint8_t *receipt_parts[3] = {
		(const uint8_t *)PQCP_SOVEREIGN_AUDIT_RECEIPT_DOMAIN,
		b->receipt_digest, NULL,
	};
	const size_t receipt_lengths[3] = {
		sizeof(PQCP_SOVEREIGN_AUDIT_RECEIPT_DOMAIN) - 1U, DIGEST_BYTES, DIGEST_BYTES,
	};
	size_t limit = MIN(p->maximum_events, x->config.maximum_batch_events);
	int ret = k_mutex_lock(&l->lock, K_FOREVER);

	if (ret != 0) {
		return ret;
	}
	/* Zephyr mutexes are recursive, so verify under this same snapshot lock. */
	ret = pqcp_sovereign_event_ledger_verify(l);
	if (ret != 0) {
		goto out;
	}
	if (l->count && c->next_sequence <
	    pqcp_sovereign_audit_internal_logical_event(l, 0U)->sequence) {
		ret = -ESTALE;
		goto out;
	}
	b->schema_version = SCHEMA;
	b->cursor_id = c->cursor_id;
	b->created_at_ms = now;
	b->policy_epoch = p->policy_epoch;
	b->format = p->format;
	b->redaction = p->redaction;
	b->events = x->storage.workspace_events;
	memcpy(b->tenant_id, c->tenant_id, sizeof(b->tenant_id));
	memcpy(b->source_anchor_digest, l->anchor_digest, DIGEST_BYTES);
	memcpy(b->source_chain_head, l->chain_head, DIGEST_BYTES);
	memcpy(b->previous_batch_digest, c->previous_batch_digest, DIGEST_BYTES);
	for (size_t i = 0U; i < l->count; ++i) {
		const struct pqcp_sovereign_event *e = pqcp_sovereign_audit_internal_logical_event(l, i);

		if (e->sequence < c->next_sequence) {
			continue;
		}
		b->scanned_through_sequence = e->sequence;
		if (!pqcp_sovereign_audit_internal_policy_matches(p, e)) {
			continue;
		}
		ret = pqcp_sovereign_event_redact(e, p->redaction, p->include_attributes,
			p->include_reasons, &x->storage.workspace_events[b->event_count]);
		if (ret != 0) {
			goto out;
		}
		/* Ordered, domain-separated chain over the original source receipts. */
		receipt_parts[2] = e->receipt_digest;
		ret = pqcp_sovereign_audit_internal_sha256_parts(receipt_parts, receipt_lengths,
			ARRAY_SIZE(receipt_parts), b->receipt_digest);
		if (ret != 0) {
			goto out;
		}
		if (b->event_count == 0U) {
			b->first_sequence = e->sequence;
		}
		b->last_sequence = e->sequence;
		b->event_count++;
		if (b->event_count == limit) {
			break;
		}
	}
	b->complete = l->count == 0U || b->scanned_through_sequence == l->next_sequence - 1U;
	ret = b->event_count == 0U ? -ENOENT : 0;
out:
	(void)k_mutex_unlock(&l->lock);
	return ret;
}

static bool overlaps(const void *a, size_t asize, const void *b, size_t bsize)
{
	uintptr_t ap = (uintptr_t)a, bp = (uintptr_t)b;

	return asize && bsize && (ap <= bp ? bp - ap < asize : ap - bp < bsize);
}

static int batch_digest(const struct pqcp_sovereign_export_batch *batch,
	uint8_t *output, size_t capacity, uint8_t digest[DIGEST_BYTES])
{
	size_t length = 0U;
	int ret = pqcp_sovereign_audit_cbor_encode_batch_body(batch, output, capacity, &length);

	if (ret == 0) {
		const uint8_t *parts[] = {(const uint8_t *)PQCP_SOVEREIGN_AUDIT_BATCH_DOMAIN, output};
		const size_t lengths[] = {sizeof(PQCP_SOVEREIGN_AUDIT_BATCH_DOMAIN) - 1U, length};

		ret = pqcp_sovereign_audit_internal_sha256_parts(parts, lengths, ARRAY_SIZE(parts), digest);
	}
	return ret;
}

/* Process-local object bytes only: never serialized or used as the wire hash. */
static int snapshot_digest(const struct pqcp_sovereign_audit_exporter *x,
	uint8_t digest[DIGEST_BYTES])
{
	const uint8_t *parts[] = {
		(const uint8_t *)&x->pending_batch, (const uint8_t *)&x->pending_policy,
		(const uint8_t *)x->pending_batch.events,
	};
	const size_t lengths[] = {
		sizeof(x->pending_batch), sizeof(x->pending_policy),
		x->pending_batch.event_count * sizeof(*x->pending_batch.events),
	};

	return pqcp_sovereign_audit_internal_sha256_parts(parts, lengths, ARRAY_SIZE(parts), digest);
}

static int pending_valid(const struct pqcp_sovereign_audit_exporter *x,
	const struct pqcp_sovereign_audit_cursor *c)
{
	const struct pqcp_sovereign_export_batch *b = &x->pending_batch;
	uint8_t workspace_digest[DIGEST_BYTES];

	if (b->schema_version != SCHEMA || b->cursor_id != c->cursor_id ||
	    c->state != PQCP_SOVEREIGN_AUDIT_CURSOR_OUTSTANDING ||
	    c->next_sequence != c->acknowledged_sequence + 1U ||
	    b->first_sequence != c->outstanding_first_sequence ||
	    b->last_sequence != c->outstanding_last_sequence ||
	    b->scanned_through_sequence != c->outstanding_scanned_sequence ||
	    b->event_count != c->outstanding_event_count ||
	    !pqcp_sovereign_audit_internal_equal(b->batch_digest, c->outstanding_batch_digest, DIGEST_BYTES) ||
	    b->events != x->storage.workspace_events || b->event_count == 0U ||
	    b->event_count > x->storage.workspace_event_capacity ||
	    b->event_count > x->config.maximum_batch_events ||
	    b->first_sequence < c->next_sequence || b->last_sequence < b->first_sequence ||
	    b->scanned_through_sequence < b->last_sequence || b->scanned_through_sequence == UINT64_MAX ||
	    b->created_at_ms < c->opened_at_ms || b->created_at_ms >= c->expires_at_ms ||
	    b->signature_length > sizeof(b->signature) ||
	    !policy_valid(&x->pending_policy) ||
	    b->policy_epoch != c->policy_epoch || b->format != x->pending_policy.format ||
	    b->redaction != x->pending_policy.redaction ||
	    memcmp(b->tenant_id, c->tenant_id, sizeof(b->tenant_id)) != 0 ||
	    b->events[0].sequence != b->first_sequence ||
	    b->events[b->event_count - 1U].sequence != b->last_sequence ||
	    !pqcp_sovereign_audit_internal_equal(b->previous_batch_digest, c->previous_batch_digest, DIGEST_BYTES)) {
		return -EBADMSG;
	}
	for (size_t i = 0U; i < b->event_count; ++i) {
		if (i && b->events[i].sequence <= b->events[i - 1U].sequence) {
			return -EBADMSG;
		}
	}
	/* Projections intentionally retain the SOURCE event digest. Their changed
	 * fields are authenticated by the batch digest/signature, not event_verify.
	 * This process-local memory hash also detects frozen-state changes in audit()
	 * without requiring an unbounded CBOR scratch allocation.
	 */
	if (snapshot_digest(x, workspace_digest) != 0 ||
	    !pqcp_sovereign_audit_internal_equal(workspace_digest, x->pending_snapshot_digest, DIGEST_BYTES)) {
		return -EBADMSG;
	}
	if (x->config.signing_enabled) {
		if (b->signature_algorithm != PQCP_SOVEREIGN_AUDIT_SIGNATURE_MLDSA || b->signature_length == 0U) {
			return -EBADMSG;
		}
		return pqcp_runtime_key_store_verify(x->config.key_store, &x->config.signing_key,
			b->batch_digest, DIGEST_BYTES, (const uint8_t *)PQCP_SOVEREIGN_AUDIT_SIGNATURE_CONTEXT,
			sizeof(PQCP_SOVEREIGN_AUDIT_SIGNATURE_CONTEXT) - 1U, b->signature, b->signature_length);
	}
	return b->signature_algorithm == PQCP_SOVEREIGN_AUDIT_SIGNATURE_NONE &&
	       b->signature_length == 0U ? 0 : -EBADMSG;
}

int pqcp_sovereign_audit_export_prepare(
	struct pqcp_sovereign_audit_exporter *x, uint64_t id,
	const struct pqcp_sovereign_audit_export_policy *p, uint64_t now,
	uint8_t *output, size_t capacity, struct pqcp_sovereign_export_batch *batch)
{
	struct pqcp_sovereign_audit_cursor *c;
	struct pqcp_sovereign_export_batch *b;
	size_t length = 0U;
	bool retry = false;
	int ret;

	if (!policy_valid(p) || output == NULL || capacity == 0U || batch == NULL || now == 0U) {
		return -EINVAL;
	}
	ret = exporter_lock(x);
	if (ret != 0) {
		return ret;
	}
	if (overlaps(output, capacity, x, sizeof(*x)) ||
	    overlaps(output, capacity, batch, sizeof(*batch)) ||
	    overlaps(output, capacity, x->storage.workspace_events,
		     x->storage.workspace_event_capacity * sizeof(*x->storage.workspace_events)) ||
	    overlaps(output, capacity, x->storage.cursors,
		     x->storage.cursor_capacity * sizeof(*x->storage.cursors))) {
		ret = -EINVAL;
		goto out;
	}
	memset(batch, 0, sizeof(*batch));
	c = find_cursor(x, id);
	ret = cursor_live(c, now);
	if (ret != 0) {
		goto out;
	}
	if (strcmp(c->tenant_id, p->tenant_id) != 0 || c->policy_epoch != p->policy_epoch) {
		ret = -EACCES;
		goto out;
	}
	b = &x->pending_batch;
	if (b->cursor_id != 0U) {
		if (b->cursor_id != id) {
			ret = -EBUSY;
			goto out;
		}
		if (!same_policy(&x->pending_policy, p)) {
			ret = -ESTALE;
			goto out;
		}
		retry = true;
		if (now < b->created_at_ms) {
			ret = -EINVAL;
			goto out;
		}
		ret = pending_valid(x, c);
		if (ret == 0) {
			uint8_t digest[DIGEST_BYTES];

			ret = batch_digest(b, output, capacity, digest);
			if (ret == 0 && !pqcp_sovereign_audit_internal_equal(digest, b->batch_digest, DIGEST_BYTES)) {
				ret = -EBADMSG;
			}
		}
		if (ret != 0) {
			goto failed_prepare;
		}
	} else {
		if ((p->require_signature || x->config.signature_required) && !x->config.signing_enabled) {
			ret = -ENOTSUP;
			goto out;
		}
		ret = collect_batch(x, c, p, now);
		if (ret == 0) {
			ret = batch_digest(b, output, capacity, b->batch_digest);
		}
		if (ret == 0 && x->config.signing_enabled) {
			ret = pqcp_runtime_key_store_sign(x->config.key_store, &x->config.signing_key,
				b->batch_digest, DIGEST_BYTES,
				(const uint8_t *)PQCP_SOVEREIGN_AUDIT_SIGNATURE_CONTEXT,
				sizeof(PQCP_SOVEREIGN_AUDIT_SIGNATURE_CONTEXT) - 1U,
				b->signature, sizeof(b->signature), &b->signature_length);
			if (ret == 0 && (b->signature_length == 0U || b->signature_length > sizeof(b->signature))) {
				ret = -EBADMSG;
			}
			if (ret == 0) {
				b->signature_algorithm = PQCP_SOVEREIGN_AUDIT_SIGNATURE_MLDSA;
			}
		}
		if (ret != 0) {
			goto failed_prepare;
		}
	}
	ret = pqcp_sovereign_audit_internal_encode_batch(b, output, capacity, &length);
	if (ret != 0) {
		goto failed_prepare;
	}
	b->encoded_length = length;
	if (!retry) {
		x->pending_policy = *p;
		ret = snapshot_digest(x, x->pending_snapshot_digest);
		if (ret != 0) {
			goto failed_prepare;
		}
		c->outstanding_first_sequence = b->first_sequence;
		c->outstanding_last_sequence = b->last_sequence;
		c->outstanding_scanned_sequence = b->scanned_through_sequence;
		c->outstanding_event_count = b->event_count;
		memcpy(c->outstanding_batch_digest, b->batch_digest, DIGEST_BYTES);
		c->state = PQCP_SOVEREIGN_AUDIT_CURSOR_OUTSTANDING;
		x->prepared_batches = pqcp_sovereign_audit_internal_add_u64(x->prepared_batches, 1U);
	} else {
		x->resumed_batches = pqcp_sovereign_audit_internal_add_u64(x->resumed_batches, 1U);
	}
	*batch = *b;
	batch->resumed = retry;
	goto out;
failed_prepare:
	/* A failed retransmission keeps the frozen batch available. */
	if (!retry) {
		release_pending(x);
	}
	pqcp_runtime_secure_zero(output, capacity);
out:
	if (ret != 0) {
		x->rejected_batches = pqcp_sovereign_audit_internal_add_u64(x->rejected_batches, 1U);
	}
	(void)k_mutex_unlock(&x->lock);
	return ret;
}

int pqcp_sovereign_audit_export_acknowledge(
	struct pqcp_sovereign_audit_exporter *x, uint64_t id, uint64_t first, uint64_t last,
	const uint8_t digest[DIGEST_BYTES], uint64_t now)
{
	struct pqcp_sovereign_audit_cursor *c;
	int ret;

	if (digest == NULL) {
		return -EINVAL;
	}
	ret = exporter_lock(x);
	if (ret != 0) {
		return ret;
	}
	c = find_cursor(x, id);
	ret = cursor_live(c, now);
	if (ret == 0 && (c->state != PQCP_SOVEREIGN_AUDIT_CURSOR_OUTSTANDING ||
	    x->pending_batch.cursor_id != id || first != c->outstanding_first_sequence ||
	    last != c->outstanding_last_sequence ||
	    !pqcp_sovereign_audit_internal_equal(digest, c->outstanding_batch_digest, DIGEST_BYTES))) {
		ret = -EBADMSG;
	}
	if (ret == 0 && now < x->pending_batch.created_at_ms) {
		ret = -EINVAL;
	}
	if (ret == 0) {
		ret = pending_valid(x, c);
	}
	if (ret == 0) {
		c->acknowledged_sequence = c->outstanding_scanned_sequence;
		c->next_sequence = c->acknowledged_sequence + 1U;
		memcpy(c->previous_batch_digest, c->outstanding_batch_digest, DIGEST_BYTES);
		c->outstanding_first_sequence = 0U;
		c->outstanding_last_sequence = 0U;
		c->outstanding_scanned_sequence = 0U;
		c->outstanding_event_count = 0U;
		memset(c->outstanding_batch_digest, 0, DIGEST_BYTES);
		c->state = PQCP_SOVEREIGN_AUDIT_CURSOR_ACTIVE;
		x->acknowledged_batches = pqcp_sovereign_audit_internal_add_u64(x->acknowledged_batches, 1U);
		release_pending(x);
	}
	(void)k_mutex_unlock(&x->lock);
	return ret;
}

int pqcp_sovereign_audit_export_close(struct pqcp_sovereign_audit_exporter *x, uint64_t id)
{
	struct pqcp_sovereign_audit_cursor *c;
	int ret = exporter_lock(x);

	if (ret != 0) {
		return ret;
	}
	c = find_cursor(x, id);
	if (c == NULL) {
		ret = -ENOENT;
	} else {
		if (x->pending_batch.cursor_id == id) {
			release_pending(x);
		}
		pqcp_runtime_secure_zero(c, sizeof(*c));
		c->state = PQCP_SOVEREIGN_AUDIT_CURSOR_CLOSED;
	}
	(void)k_mutex_unlock(&x->lock);
	return ret;
}

int pqcp_sovereign_audit_export_expire(struct pqcp_sovereign_audit_exporter *x,
	uint64_t now, uint32_t *expired_count)
{
	int ret;

	if (expired_count == NULL || now == 0U) {
		return -EINVAL;
	}
	*expired_count = 0U;
	ret = exporter_lock(x);
	if (ret != 0) {
		return ret;
	}
	for (size_t i = 0U; i < x->storage.cursor_capacity; ++i) {
		struct pqcp_sovereign_audit_cursor *c = &x->storage.cursors[i];

		if (c->occupied && now >= c->expires_at_ms) {
			if (x->pending_batch.cursor_id == c->cursor_id) {
				release_pending(x);
			}
			pqcp_runtime_secure_zero(c, sizeof(*c));
			c->state = PQCP_SOVEREIGN_AUDIT_CURSOR_EXPIRED;
			if (*expired_count != UINT32_MAX) {
				(*expired_count)++;
			}
		}
	}
	(void)k_mutex_unlock(&x->lock);
	return 0;
}

int pqcp_sovereign_audit_exporter_audit(struct pqcp_sovereign_audit_exporter *x)
{
	size_t outstanding = 0U;
	int ret = exporter_lock(x);

	if (ret != 0) {
		return ret;
	}
	ret = pqcp_sovereign_event_ledger_verify(x->ledger);
	for (size_t i = 0U; ret == 0 && i < x->storage.cursor_capacity; ++i) {
		const struct pqcp_sovereign_audit_cursor *c = &x->storage.cursors[i];

		if (!c->occupied) {
			continue;
		}
		if (c->schema_version != SCHEMA || c->generation == 0U || c->cursor_id == 0U ||
		    c->cursor_id >= x->next_cursor_id || c->generation >= x->next_generation ||
		    c->next_sequence == 0U || c->next_sequence != c->acknowledged_sequence + 1U ||
		    c->opened_at_ms == 0U || c->expires_at_ms <= c->opened_at_ms || c->policy_epoch == 0U ||
		    !pqcp_sovereign_audit_internal_text_valid(c->tenant_id, sizeof(c->tenant_id), false) ||
		    !pqcp_sovereign_audit_internal_text_valid(c->consumer_id, sizeof(c->consumer_id), false) ||
		    (c->state != PQCP_SOVEREIGN_AUDIT_CURSOR_ACTIVE && c->state != PQCP_SOVEREIGN_AUDIT_CURSOR_OUTSTANDING)) {
			ret = -EBADMSG;
			break;
		}
		for (size_t j = 0U; j < i; ++j) {
			if (x->storage.cursors[j].occupied && x->storage.cursors[j].cursor_id == c->cursor_id) {
				ret = -EBADMSG;
			}
		}
		if (c->state == PQCP_SOVEREIGN_AUDIT_CURSOR_OUTSTANDING) {
			const struct pqcp_sovereign_export_batch *b = &x->pending_batch;

			outstanding++;
			if (b->cursor_id != c->cursor_id || b->event_count == 0U ||
			    b->event_count > x->storage.workspace_event_capacity ||
			    b->events != x->storage.workspace_events ||
			    b->event_count != c->outstanding_event_count ||
			    b->first_sequence != c->outstanding_first_sequence ||
			    b->last_sequence != c->outstanding_last_sequence ||
			    b->scanned_through_sequence != c->outstanding_scanned_sequence ||
			    !pqcp_sovereign_audit_internal_equal(b->batch_digest, c->outstanding_batch_digest, DIGEST_BYTES)) {
				ret = -EBADMSG;
			}
			if (ret == 0) {
				ret = pending_valid(x, c);
			}
		}
	}
	if (outstanding > 1U || ((x->pending_batch.cursor_id != 0U) != (outstanding == 1U))) {
		ret = -EBADMSG;
	}
	(void)k_mutex_unlock(&x->lock);
	return ret;
}
