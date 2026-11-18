/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Secure message queue, replay protection, fragmentation, ratchet, topic
 * registry, group membership and delivery tracking.
 */

#include "edge_security_internal.h"
#include "test_common.h"

/* ------------------------------------------------------------------ */
/* Message queue                                                       */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_message mstore[3];
static struct pqcp_edge_message_queue mq;
static uint8_t mkey[PQCP_EDGE_KEY_BYTES];

static void mq_setup(size_t capacity)
{
	zassert_true(capacity <= ARRAY_SIZE(mstore));
	zassert_equal(pqcp_edge_message_queue_init(&mq, mstore, capacity), 0);
	edge_key(mkey, 7U);
}

static void make_msg(struct pqcp_edge_message *m, uint8_t id_byte,
		     uint64_t sequence,
		     enum pqcp_edge_message_priority priority,
		     const char *consumer, const char *topic)
{
	memset(m, 0, sizeof(*m));
	memset(m->message_id, id_byte, sizeof(m->message_id));
	SETSTR(m->producer_id, "prod-1");
	SETSTR(m->consumer_id, consumer);
	SETSTR(m->topic, topic);
	m->producer_epoch = 1U;
	m->sequence = sequence;
	m->created_at_ms = T0;
	m->expires_at_ms = T0 + 10000U;
	m->not_before_ms = T0;
	m->maximum_attempts = 3U;
	m->priority = priority;
	m->guarantee = PQCP_EDGE_DELIVERY_AT_LEAST_ONCE;
	memcpy(m->payload, "hello-edge", 10U);
	m->payload[10] = id_byte;
	m->payload_length = 11U;
}

static void submit(const struct pqcp_edge_message *m, uint64_t now)
{
	bool replayed = true;

	zassert_equal(pqcp_edge_message_submit(&mq, m, mkey, now, &replayed),
		      0);
	zassert_false(replayed);
}

ZTEST(edge_security, test_queue_rejects_invalid_arguments)
{
	static struct pqcp_edge_message_queue raw;
	struct pqcp_edge_message m;
	struct pqcp_edge_message *out = NULL;
	uint8_t id[PQCP_EDGE_MESSAGE_ID_BYTES] = { 1 };
	uint32_t changed = 0U;
	bool replayed = false;

	zassert_equal(pqcp_edge_message_queue_init(NULL, mstore, 3U), -EINVAL);
	zassert_equal(pqcp_edge_message_queue_init(&mq, NULL, 3U), -EINVAL);
	zassert_equal(pqcp_edge_message_queue_init(&mq, mstore, 0U), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_msg(&m, 1U, 1U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	edge_key(mkey, 7U);
	zassert_equal(pqcp_edge_message_submit(&raw, &m, mkey, T0,
		&replayed), -EINVAL);
	zassert_equal(pqcp_edge_message_next(&raw, "c1", "t1", T0, &out),
		      -EINVAL);
	zassert_equal(pqcp_edge_message_acknowledge(&raw, id, T0), -EINVAL);
	zassert_equal(pqcp_edge_message_retry(&raw, id, T0, -EIO), -EINVAL);
	zassert_equal(pqcp_edge_message_cancel(&raw, id), -EINVAL);
	zassert_equal(pqcp_edge_message_tick(&raw, T0, &changed), -EINVAL);
	zassert_equal(pqcp_edge_message_queue_audit(&raw, mkey), -EINVAL);

	mq_setup(3U);
	zassert_equal(pqcp_edge_message_submit(&mq, NULL, mkey, T0,
		&replayed), -EINVAL);
	zassert_equal(pqcp_edge_message_submit(&mq, &m, NULL, T0,
		&replayed), -EINVAL);
	zassert_equal(pqcp_edge_message_submit(&mq, &m, mkey, T0, NULL),
		      -EINVAL);

#define EXPECT_BAD(mutation)                                              \
	do {                                                              \
		make_msg(&m, 1U, 1U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1"); \
		mutation;                                                 \
		zassert_equal(pqcp_edge_message_submit(&mq, &m, mkey, T0, \
			&replayed), -EINVAL, #mutation);                  \
	} while (0)
	EXPECT_BAD(memset(m.message_id, 0, sizeof(m.message_id)));
	EXPECT_BAD(m.producer_id[0] = '\0');
	EXPECT_BAD(m.consumer_id[0] = '\0');
	EXPECT_BAD(m.topic[0] = '\0');
	EXPECT_BAD(m.producer_epoch = 0U);
	EXPECT_BAD(m.sequence = 0U);
	EXPECT_BAD(m.payload_length = 0U);
	EXPECT_BAD(m.payload_length = sizeof(m.payload) + 1U);
	EXPECT_BAD(m.maximum_attempts = 0U);
	EXPECT_BAD(m.priority = (enum pqcp_edge_message_priority)9);
	EXPECT_BAD(m.guarantee = (enum pqcp_edge_delivery_guarantee)9);
	EXPECT_BAD(m.state = (enum pqcp_edge_message_state)99);
	EXPECT_BAD(m.expires_at_ms = T0);
	EXPECT_BAD(m.created_at_ms = T0 + 1U);
	EXPECT_BAD(m.not_before_ms = m.expires_at_ms + 1U);
#undef EXPECT_BAD
	zassert_equal(mq.accepted_count, 0U);
	zassert_equal(pqcp_edge_message_queue_audit(&mq, mkey), 0);

	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0, NULL),
		      -EINVAL);
	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0, &out),
		      -EAGAIN);
	zassert_is_null(out);
	zassert_equal(pqcp_edge_message_acknowledge(&mq, NULL, T0), -EINVAL);
	zassert_equal(pqcp_edge_message_acknowledge(&mq, id, T0), -ENOENT);
	zassert_equal(pqcp_edge_message_retry(&mq, id, T0, 0), -EINVAL);
	zassert_equal(pqcp_edge_message_retry(&mq, NULL, T0, -EIO), -EINVAL);
	zassert_equal(pqcp_edge_message_retry(&mq, id, T0, -EIO), -ENOENT);
	zassert_equal(pqcp_edge_message_cancel(&mq, NULL), -EINVAL);
	zassert_equal(pqcp_edge_message_cancel(&mq, id), -ENOENT);
	zassert_equal(pqcp_edge_message_tick(&mq, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_message_queue_audit(&mq, NULL), -EINVAL);
}

ZTEST(edge_security, test_queue_delivery_order_and_filters)
{
	struct pqcp_edge_message m;
	struct pqcp_edge_message *out = NULL;

	mq_setup(3U);
	make_msg(&m, 1U, 1U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	submit(&m, T0);
	make_msg(&m, 2U, 2U, PQCP_EDGE_MESSAGE_CRITICAL, "c1", "t1");
	submit(&m, T0);
	make_msg(&m, 3U, 3U, PQCP_EDGE_MESSAGE_NORMAL, "c2", "t2");
	m.not_before_ms = T0 + 500U;
	submit(&m, T0);

	/* Hash chain links each message to its predecessor. */
	zassert_mem_equal(mstore[1].previous_digest,
			  mstore[0].message_digest, PQCP_EDGE_DIGEST_BYTES);
	zassert_mem_equal(mq.chain_head, mstore[2].message_digest,
			  PQCP_EDGE_DIGEST_BYTES);

	/* The third message is not yet deliverable. */
	zassert_equal(pqcp_edge_message_next(&mq, "c2", "t2", T0, &out),
		      -EAGAIN);
	/* Wrong consumer or topic never sees the message. */
	zassert_equal(pqcp_edge_message_next(&mq, "c2", "t1", T0 + 500U,
		&out), -EAGAIN);
	zassert_equal(pqcp_edge_message_next(&mq, "c3", NULL, T0 + 500U,
		&out), -EAGAIN);

	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0, &out), 0);
	zassert_equal(out->message_id[0], 2U);
	zassert_equal(out->state, PQCP_EDGE_MESSAGE_IN_FLIGHT);
	zassert_equal(out->attempt_count, 1U);
	zassert_equal(pqcp_edge_message_next(&mq, "", "", T0, &out), 0);
	zassert_equal(out->message_id[0], 1U);
	/* In-flight messages are not handed out twice. */
	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0, &out),
		      -EAGAIN);
	zassert_equal(pqcp_edge_message_next(&mq, "c2", "t2", T0 + 500U,
		&out), 0);
	zassert_equal(out->message_id[0], 3U);

	zassert_equal(pqcp_edge_message_acknowledge(&mq, mstore[0].message_id,
		T0 + 10U), 0);
	zassert_equal(mq.acknowledged_count, 1U);
	zassert_equal(pqcp_edge_message_acknowledge(&mq, mstore[0].message_id,
		T0 + 11U), -EALREADY);
	zassert_equal(mq.acknowledged_count, 1U);
	zassert_equal(pqcp_edge_message_queue_audit(&mq, mkey), 0);
}

ZTEST(edge_security, test_queue_submission_is_exactly_idempotent)
{
	struct pqcp_edge_message m;
	struct pqcp_edge_message snap[3];
	uint8_t head[PQCP_EDGE_DIGEST_BYTES];
	bool replayed = false;

	mq_setup(3U);
	make_msg(&m, 1U, 1U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	submit(&m, T0);
	memcpy(snap, mstore, sizeof(snap));
	memcpy(head, mq.chain_head, sizeof(head));

	/* Byte-identical resubmission is acknowledged as a replay. */
	zassert_equal(pqcp_edge_message_submit(&mq, &m, mkey, T0 + 1U,
		&replayed), 0);
	zassert_true(replayed);
	zassert_equal(mq.accepted_count, 1U);
	zassert_mem_equal(mq.chain_head, head, sizeof(head));
	zassert_mem_equal(mstore, snap, sizeof(snap));

	/* Same id but different payload is a conflict, not a replay. */
	m.payload[0] ^= 0xffU;
	zassert_equal(pqcp_edge_message_submit(&mq, &m, mkey, T0 + 1U,
		&replayed), -EKEYREJECTED);
	zassert_false(replayed);
	m.payload[0] ^= 0xffU;
	m.sequence = 99U;
	zassert_equal(pqcp_edge_message_submit(&mq, &m, mkey, T0 + 1U,
		&replayed), -EKEYREJECTED);
	m.sequence = 1U;
	m.producer_epoch = 2U;
	zassert_equal(pqcp_edge_message_submit(&mq, &m, mkey, T0 + 1U,
		&replayed), -EKEYREJECTED);
	zassert_mem_equal(mstore, snap, sizeof(snap));
	zassert_equal(mq.accepted_count, 1U);
	zassert_mem_equal(mq.chain_head, head, sizeof(head));
}

ZTEST(edge_security, test_queue_resubmission_must_match_all_routing_fields)
{
	struct pqcp_edge_message m;
	bool replayed = false;
	int ret;

	mq_setup(3U);
	make_msg(&m, 1U, 1U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	submit(&m, T0);

	/* Same id, payload, sequence and epoch but a different consumer. */
	SETSTR(m.consumer_id, "other-consumer");
	SETSTR(m.topic, "other-topic");
	ret = pqcp_edge_message_submit(&mq, &m, mkey, T0 + 1U, &replayed);
	zassert_not_equal(ret, 0);
	zassert_false(replayed);
	/* Only the original routing is queued; nothing was changed. */
	zassert_equal(mq.accepted_count, 1U);
	/* A byte-identical resubmission is still an idempotent replay. */
	make_msg(&m, 1U, 1U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	ret = pqcp_edge_message_submit(&mq, &m, mkey, T0 + 2U, &replayed);
	zassert_equal(ret, 0);
	zassert_true(replayed);
	zassert_equal(mq.accepted_count, 1U);
}

ZTEST(edge_security, test_queue_retry_dead_letter_and_expiry)
{
	struct pqcp_edge_message m;
	struct pqcp_edge_message *out = NULL;
	uint32_t changed = 0U;

	mq_setup(3U);
	make_msg(&m, 1U, 1U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	m.maximum_attempts = 2U;
	submit(&m, T0);

	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0, &out), 0);
	zassert_equal(pqcp_edge_message_retry(&mq, out->message_id,
		T0 + 100U, -EIO), 0);
	zassert_equal(out->state, PQCP_EDGE_MESSAGE_RETRY_WAIT);
	zassert_equal(out->not_before_ms, T0 + 100U);
	zassert_equal(mq.retried_count, 1U);
	/* Not deliverable before the backoff elapses. */
	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0 + 99U,
		&out), -EAGAIN);
	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0 + 100U,
		&out), 0);
	zassert_equal(out->attempt_count, 2U);

	/* Attempts exhausted: retry dead-letters instead of re-queueing. */
	zassert_equal(pqcp_edge_message_retry(&mq, out->message_id,
		T0 + 200U, -EIO), -EOVERFLOW);
	zassert_equal(out->state, PQCP_EDGE_MESSAGE_DEAD_LETTER);
	zassert_equal(mq.dead_letter_count, 1U);
	zassert_equal(pqcp_edge_message_retry(&mq, out->message_id,
		T0 + 200U, -EIO), -ESTALE);
	zassert_equal(pqcp_edge_message_acknowledge(&mq, out->message_id,
		T0 + 201U), -ESTALE);
	zassert_equal(pqcp_edge_message_cancel(&mq, out->message_id),
		      -EALREADY);
	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0 + 300U,
		&out), -EAGAIN);

	/* A retry scheduled past expiry expires the message. */
	make_msg(&m, 2U, 2U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	m.expires_at_ms = T0 + 1000U;
	submit(&m, T0);
	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0, &out), 0);
	zassert_equal(pqcp_edge_message_retry(&mq, out->message_id,
		T0 + 1000U, -EIO), -ETIMEDOUT);
	zassert_equal(out->state, PQCP_EDGE_MESSAGE_EXPIRED);
	zassert_equal(mq.expired_count, 1U);

	/* Tick: RETRY_WAIT -> QUEUED, stale -> EXPIRED. */
	make_msg(&m, 3U, 3U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	m.expires_at_ms = T0 + 5000U;
	submit(&m, T0);
	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0, &out), 0);
	zassert_equal(pqcp_edge_message_retry(&mq, out->message_id,
		T0 + 50U, -EIO), 0);
	zassert_equal(pqcp_edge_message_tick(&mq, T0 + 49U, &changed), 0);
	zassert_equal(changed, 0U);
	zassert_equal(pqcp_edge_message_tick(&mq, T0 + 50U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(out->state, PQCP_EDGE_MESSAGE_QUEUED);
	zassert_equal(pqcp_edge_message_tick(&mq, T0 + 5000U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(out->state, PQCP_EDGE_MESSAGE_EXPIRED);
	zassert_equal(pqcp_edge_message_acknowledge(&mq, out->message_id,
		T0 + 5001U), -ESTALE);
}

ZTEST(edge_security, test_queue_ack_after_expiry_is_refused)
{
	struct pqcp_edge_message m;
	struct pqcp_edge_message *out = NULL;

	mq_setup(3U);
	make_msg(&m, 1U, 1U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	m.expires_at_ms = T0 + 100U;
	submit(&m, T0);
	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0, &out), 0);
	zassert_equal(pqcp_edge_message_acknowledge(&mq, out->message_id,
		T0 + 100U), -ETIMEDOUT);
	zassert_equal(out->state, PQCP_EDGE_MESSAGE_EXPIRED);
	zassert_equal(mq.acknowledged_count, 0U);
	zassert_equal(mq.expired_count, 1U);
}

ZTEST(edge_security, test_queue_cancel_and_in_flight_dead_letter)
{
	struct pqcp_edge_message m;
	struct pqcp_edge_message *out = NULL;
	uint32_t changed = 0U;

	mq_setup(3U);
	make_msg(&m, 1U, 1U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	submit(&m, T0);
	zassert_equal(pqcp_edge_message_cancel(&mq, m.message_id), 0);
	zassert_equal(mstore[0].state, PQCP_EDGE_MESSAGE_CANCELLED);
	zassert_equal(pqcp_edge_message_cancel(&mq, m.message_id), -EALREADY);
	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0, &out),
		      -EAGAIN);

	make_msg(&m, 2U, 2U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	m.maximum_attempts = 1U;
	submit(&m, T0);
	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0, &out), 0);
	/* An unacknowledged final attempt is dead-lettered by the tick. */
	zassert_equal(pqcp_edge_message_tick(&mq, T0 + 1U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(out->state, PQCP_EDGE_MESSAGE_DEAD_LETTER);
	zassert_equal(mq.dead_letter_count, 1U);
}

ZTEST(edge_security, test_queue_capacity_exhaustion_and_recycling)
{
	struct pqcp_edge_message m;
	struct pqcp_edge_message snap[2];
	struct pqcp_edge_message *out = NULL;
	bool replayed = false;

	mq_setup(2U);
	make_msg(&m, 1U, 1U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	submit(&m, T0);
	make_msg(&m, 2U, 2U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	m.created_at_ms = T0 + 1U;
	submit(&m, T0 + 1U);
	memcpy(snap, mstore, sizeof(snap));

	/* Live messages are never evicted to make room. */
	make_msg(&m, 3U, 3U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	zassert_equal(pqcp_edge_message_submit(&mq, &m, mkey, T0 + 2U,
		&replayed), -ENOSPC);
	zassert_mem_equal(mstore, snap, sizeof(snap));
	zassert_equal(mq.accepted_count, 2U);

	/* A terminal message frees the oldest slot for reuse. */
	zassert_equal(pqcp_edge_message_next(&mq, "c1", "t1", T0 + 2U, &out),
		      0);
	zassert_equal(pqcp_edge_message_acknowledge(&mq, out->message_id,
		T0 + 3U), 0);
	zassert_equal(pqcp_edge_message_submit(&mq, &m, mkey, T0 + 4U,
		&replayed), 0);
	zassert_false(replayed);
	zassert_equal(mq.accepted_count, 3U);
	zassert_equal(pqcp_edge_message_queue_audit(&mq, mkey), 0);
}

ZTEST(edge_security, test_queue_audit_detects_tampering)
{
	struct pqcp_edge_message m;
	uint8_t other_key[PQCP_EDGE_KEY_BYTES];

	mq_setup(3U);
	make_msg(&m, 1U, 1U, PQCP_EDGE_MESSAGE_NORMAL, "c1", "t1");
	submit(&m, T0);
	make_msg(&m, 2U, 2U, PQCP_EDGE_MESSAGE_HIGH, "c1", "t1");
	submit(&m, T0);
	zassert_equal(pqcp_edge_message_queue_audit(&mq, mkey), 0);

	/* Wrong authentication key. */
	edge_key(other_key, 99U);
	zassert_equal(pqcp_edge_message_queue_audit(&mq, other_key),
		      -EBADMSG);
	/* Payload corruption. */
	mstore[0].payload[0] ^= 1U;
	zassert_equal(pqcp_edge_message_queue_audit(&mq, mkey), -EBADMSG);
	mstore[0].payload[0] ^= 1U;
	/* Header tampering is covered by the digest and tag. */
	mstore[0].expires_at_ms += 1U;
	zassert_equal(pqcp_edge_message_queue_audit(&mq, mkey), -EBADMSG);
	mstore[0].expires_at_ms -= 1U;
	mstore[1].authentication_tag[3] ^= 1U;
	zassert_equal(pqcp_edge_message_queue_audit(&mq, mkey), -EBADMSG);
	mstore[1].authentication_tag[3] ^= 1U;
	zassert_equal(pqcp_edge_message_queue_audit(&mq, mkey), 0);
}

/* ------------------------------------------------------------------ */
/* Replay guard                                                        */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_replay_entry rpstore[2];
static struct pqcp_edge_replay_guard rg;

ZTEST(edge_security, test_replay_guard_rejects_invalid_arguments)
{
	static struct pqcp_edge_replay_guard raw;
	uint32_t expired = 0U;
	char unterminated[PQCP_EDGE_ID_MAX_CHARS];

	zassert_equal(pqcp_edge_replay_guard_init(NULL, rpstore, 2U, 8U),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_guard_init(&rg, NULL, 2U, 8U),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_guard_init(&rg, rpstore, 0U, 8U),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_guard_init(&rg, rpstore, 2U, 0U),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_guard_init(&rg, rpstore, 2U, 65U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_replay_accept(&raw, "p", 1U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_advance_epoch(&raw, "p", 2U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_expire(&raw, T0, &expired), -EINVAL);
	zassert_equal(pqcp_edge_replay_guard_audit(&raw), -EINVAL);

	zassert_equal(pqcp_edge_replay_guard_init(&rg, rpstore, 2U, 8U), 0);
	memset(unterminated, 'x', sizeof(unterminated));
	zassert_equal(pqcp_edge_replay_accept(&rg, NULL, 1U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_accept(&rg, "", 1U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_accept(&rg, unterminated, 1U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 0U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 0U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_advance_epoch(&rg, NULL, 2U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_advance_epoch(&rg, "p", 0U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_replay_advance_epoch(&rg, "p", 2U, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_replay_expire(&rg, T0, NULL), -EINVAL);
	zassert_equal(rg.accepted_count, 0U);
	zassert_false(rpstore[0].occupied);
}

ZTEST(edge_security, test_replay_guard_window_semantics)
{
	zassert_equal(pqcp_edge_replay_guard_init(&rg, rpstore, 2U, 4U), 0);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 10U, T0), 0);
	/* Exact duplicate. */
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 10U, T0),
		      -EALREADY);
	zassert_equal(rg.replay_count, 1U);

	/* Forward jump within the window keeps old sequences replayable. */
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 12U, T0), 0);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 10U, T0),
		      -EALREADY);
	/* Late but unseen sequence inside the window is accepted once. */
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 11U, T0), 0);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 11U, T0),
		      -EALREADY);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 12U, T0),
		      -EALREADY);

	/* Window of 4 around highest=12 covers 9..12; 8 is stale. */
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 9U, T0), 0);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 8U, T0),
		      -ESTALE);
	zassert_equal(rg.stale_count, 1U);

	/* A large forward jump resets the window; the past becomes stale. */
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 100U, T0), 0);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 12U, T0),
		      -ESTALE);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 100U, T0),
		      -EALREADY);
	zassert_equal(pqcp_edge_replay_guard_audit(&rg), 0);
}

ZTEST(edge_security, test_replay_guard_epochs_are_monotonic)
{
	zassert_equal(pqcp_edge_replay_guard_init(&rg, rpstore, 2U, 8U), 0);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 2U, 5U, T0), 0);
	/* Older epoch is stale even with a fresh sequence number. */
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 1U, 50U, T0),
		      -ESTALE);
	zassert_equal(rpstore[0].epoch, 2U);
	zassert_equal(rpstore[0].highest_sequence, 5U);

	/* Epoch advance requires strictly greater epoch. */
	zassert_equal(pqcp_edge_replay_advance_epoch(&rg, "p", 2U, T0),
		      -ESTALE);
	zassert_equal(pqcp_edge_replay_advance_epoch(&rg, "p", 1U, T0),
		      -ESTALE);
	zassert_equal(pqcp_edge_replay_advance_epoch(&rg, "p", 3U, T0 + 1U),
		      0);
	zassert_equal(rpstore[0].epoch, 3U);
	zassert_equal(rpstore[0].highest_sequence, 0U);
	zassert_equal(pqcp_edge_replay_guard_audit(&rg), 0);
	/* Sequence numbers restart in the new epoch, and old ones die. */
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 3U, 1U, T0 + 2U), 0);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 3U, 1U, T0 + 2U),
		      -EALREADY);
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 2U, 6U, T0 + 2U),
		      -ESTALE);
	/* An implicit epoch bump through accept also resets the window. */
	zassert_equal(pqcp_edge_replay_accept(&rg, "p", 4U, 1U, T0 + 3U), 0);
	zassert_equal(rpstore[0].epoch, 4U);
}

ZTEST(edge_security, test_replay_guard_capacity_expiry_and_audit)
{
	uint32_t expired = 0U;
	struct pqcp_edge_replay_entry snap[2];

	zassert_equal(pqcp_edge_replay_guard_init(&rg, rpstore, 2U, 8U), 0);
	zassert_equal(pqcp_edge_replay_accept(&rg, "a", 1U, 1U, T0), 0);
	zassert_equal(pqcp_edge_replay_accept(&rg, "b", 1U, 1U, T0 + 10U), 0);
	memcpy(snap, rpstore, sizeof(snap));
	/* Fail closed on a new producer when the table is full. */
	zassert_equal(pqcp_edge_replay_accept(&rg, "c", 1U, 1U, T0 + 11U),
		      -ENOSPC);
	zassert_mem_equal(rpstore, snap, sizeof(snap));

	zassert_equal(pqcp_edge_replay_expire(&rg, T0 + 5U, &expired), 0);
	zassert_equal(expired, 1U);
	zassert_equal(pqcp_edge_replay_accept(&rg, "c", 1U, 1U, T0 + 11U), 0);
	zassert_equal(pqcp_edge_replay_guard_audit(&rg), 0);

	rpstore[0].window_bits = 0U;
	zassert_equal(pqcp_edge_replay_guard_audit(&rg), -EBADMSG);
	rpstore[0].window_bits = 1U;
	rpstore[1] = rpstore[0];
	zassert_equal(pqcp_edge_replay_guard_audit(&rg), -EEXIST);
}

/* ------------------------------------------------------------------ */
/* Fragment manager                                                    */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_reassembly fgstore[2];
static struct pqcp_edge_fragment_manager fm;
static uint8_t fg_payload[600];
static uint8_t fg_out[1024];
static uint8_t fg_id[PQCP_EDGE_MESSAGE_ID_BYTES];

static void fragment_setup(void)
{
	zassert_equal(pqcp_edge_fragment_manager_init(
		&fm, fgstore, ARRAY_SIZE(fgstore)), 0);
	for (size_t i = 0U; i < sizeof(fg_payload); ++i) {
		fg_payload[i] = (uint8_t)(i * 31U + 7U);
	}
	memset(fg_id, 0x42, sizeof(fg_id));
	memset(fg_out, 0xee, sizeof(fg_out));
}

ZTEST(edge_security, test_fragment_rejects_invalid_arguments)
{
	static struct pqcp_edge_fragment_manager raw;
	static struct pqcp_edge_fragment f;
	static uint8_t big[64U * 256U + 1U];
	bool complete = true;
	size_t length = 99U;
	uint32_t expired = 0U;
	uint8_t zero_id[PQCP_EDGE_MESSAGE_ID_BYTES] = { 0 };

	zassert_equal(pqcp_edge_fragment_manager_init(NULL, fgstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_fragment_manager_init(&fm, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_fragment_manager_init(&fm, fgstore, 0U),
		      -EINVAL);

	fragment_setup();
	zassert_equal(pqcp_edge_message_fragment(NULL, fg_payload, 10U, 0U,
		&f), -EINVAL);
	zassert_equal(pqcp_edge_message_fragment(fg_id, NULL, 10U, 0U, &f),
		      -EINVAL);
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload, 0U, 0U,
		&f), -EINVAL);
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload, 10U, 0U,
		NULL), -EINVAL);
	zassert_equal(pqcp_edge_message_fragment(zero_id, fg_payload, 10U,
		0U, &f), -EINVAL);
	/* Index beyond the fragment count, and payload above 64 fragments. */
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload, 600U,
		3U, &f), -E2BIG);
	zassert_equal(pqcp_edge_message_fragment(fg_id, big, sizeof(big),
		0U, &f), -E2BIG);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload, 600U, 0U,
		&f), 0);
	zassert_equal(pqcp_edge_fragment_accept(&raw, &f, fg_out,
		sizeof(fg_out), T0, 100U, &complete, &length), -EINVAL);
	zassert_equal(pqcp_edge_fragment_expire(&raw, T0, &expired),
		      -EINVAL);
	zassert_equal(pqcp_edge_fragment_manager_audit(&raw), -EINVAL);

	zassert_equal(pqcp_edge_fragment_accept(&fm, NULL, fg_out,
		sizeof(fg_out), T0, 100U, &complete, &length), -EINVAL);
	zassert_equal(pqcp_edge_fragment_accept(&fm, &f, fg_out,
		sizeof(fg_out), T0, 100U, NULL, &length), -EINVAL);
	zassert_equal(pqcp_edge_fragment_accept(&fm, &f, fg_out,
		sizeof(fg_out), T0, 100U, &complete, NULL), -EINVAL);
	{
		struct pqcp_edge_fragment bad = f;

		bad.fragment_index = bad.fragment_count;
		zassert_equal(pqcp_edge_fragment_accept(&fm, &bad, fg_out,
			sizeof(fg_out), T0, 100U, &complete, &length),
			-EINVAL);
		bad = f; bad.fragment_count = 65U;
		zassert_equal(pqcp_edge_fragment_accept(&fm, &bad, fg_out,
			sizeof(fg_out), T0, 100U, &complete, &length),
			-EINVAL);
		bad = f; bad.payload_length = 0U;
		zassert_equal(pqcp_edge_fragment_accept(&fm, &bad, fg_out,
			sizeof(fg_out), T0, 100U, &complete, &length),
			-EINVAL);
		bad = f; bad.offset = bad.total_length;
		zassert_equal(pqcp_edge_fragment_accept(&fm, &bad, fg_out,
			sizeof(fg_out), T0, 100U, &complete, &length),
			-EINVAL);
		bad = f; bad.total_length = 0U;
		zassert_equal(pqcp_edge_fragment_accept(&fm, &bad, fg_out,
			sizeof(fg_out), T0, 100U, &complete, &length),
			-EINVAL);
	}
	zassert_equal(pqcp_edge_fragment_manager_audit(&fm), 0);
	zassert_equal(pqcp_edge_fragment_expire(&fm, T0, NULL), -EINVAL);
}

ZTEST(edge_security, test_fragment_out_of_order_reassembly)
{
	static struct pqcp_edge_fragment f[3];
	bool complete = true;
	size_t length = 0U;

	fragment_setup();
	for (uint16_t i = 0U; i < 3U; ++i) {
		zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload,
			sizeof(fg_payload), i, &f[i]), 0);
		zassert_equal(f[i].fragment_count, 3U);
		zassert_equal(f[i].offset, i * 256U);
	}
	zassert_equal(f[2].payload_length, 600U - 512U);

	zassert_equal(pqcp_edge_fragment_accept(&fm, &f[2], fg_out,
		sizeof(fg_out), T0, 1000U, &complete, &length), 0);
	zassert_false(complete);
	zassert_equal(length, 0U);
	zassert_equal(pqcp_edge_fragment_accept(&fm, &f[0], fg_out,
		sizeof(fg_out), T0 + 1U, 1000U, &complete, &length), 0);
	zassert_false(complete);
	/* Exact duplicate is refused and changes nothing. */
	zassert_equal(pqcp_edge_fragment_accept(&fm, &f[0], fg_out,
		sizeof(fg_out), T0 + 2U, 1000U, &complete, &length), -EALREADY);
	zassert_equal(fgstore[0].received_count, 2U);
	zassert_equal(pqcp_edge_fragment_manager_audit(&fm), 0);

	zassert_equal(pqcp_edge_fragment_accept(&fm, &f[1], fg_out,
		sizeof(fg_out), T0 + 3U, 1000U, &complete, &length), 0);
	zassert_true(complete);
	zassert_equal(length, sizeof(fg_payload));
	zassert_mem_equal(fg_out, fg_payload, sizeof(fg_payload));
	zassert_false(fgstore[0].occupied);
	zassert_equal(fm.completed_count, 1U);
	zassert_equal(pqcp_edge_fragment_manager_audit(&fm), 0);
}

ZTEST(edge_security, test_fragment_tamper_and_conflict_rejection)
{
	static struct pqcp_edge_fragment f0;
	static struct pqcp_edge_fragment f1;
	static struct pqcp_edge_fragment evil;
	static struct pqcp_edge_fragment meta;
	uint8_t snapshot[sizeof(fg_out)];
	bool complete = true;
	size_t length = 0U;

	fragment_setup();
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload,
		sizeof(fg_payload), 0U, &f0), 0);
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload,
		sizeof(fg_payload), 1U, &f1), 0);

	/* A fragment whose digest does not match is rejected up front and
	 * does not allocate a reassembly slot.
	 */
	evil = f0;
	evil.payload[3] ^= 0x80U;
	zassert_equal(pqcp_edge_fragment_accept(&fm, &evil, fg_out,
		sizeof(fg_out), T0, 1000U, &complete, &length), -EBADMSG);
	zassert_equal(fm.rejected_count, 1U);
	zassert_false(fgstore[0].occupied);

	zassert_equal(pqcp_edge_fragment_accept(&fm, &f0, fg_out,
		sizeof(fg_out), T0, 1000U, &complete, &length), 0);
	memcpy(snapshot, fg_out, sizeof(snapshot));

	/* Same index, different content (valid digest): conflict. */
	evil = f0;
	evil.payload[3] ^= 0x80U;
	zassert_equal(pqcp_edge_internal_sha256(evil.payload,
		evil.payload_length, evil.payload_digest), 0);
	zassert_equal(pqcp_edge_fragment_accept(&fm, &evil, fg_out,
		sizeof(fg_out), T0 + 1U, 1000U, &complete, &length),
		-EKEYREJECTED);
	zassert_mem_equal(fg_out, snapshot, sizeof(snapshot));

	/* Same message id, inconsistent framing: conflict. */
	meta = f1;
	meta.total_length += 1U;
	zassert_equal(pqcp_edge_fragment_accept(&fm, &meta, fg_out,
		sizeof(fg_out), T0 + 1U, 1000U, &complete, &length),
		-EKEYREJECTED);
	meta = f1;
	meta.fragment_count = 4U;
	zassert_equal(pqcp_edge_fragment_accept(&fm, &meta, fg_out,
		sizeof(fg_out), T0 + 1U, 1000U, &complete, &length),
		-EKEYREJECTED);
	/* Same message id but another output buffer: conflict. */
	zassert_equal(pqcp_edge_fragment_accept(&fm, &f1, fg_out + 1,
		sizeof(fg_out) - 1U, T0 + 1U, 1000U, &complete, &length),
		-EKEYREJECTED);
	zassert_mem_equal(fg_out, snapshot, sizeof(snapshot));
	zassert_equal(fgstore[0].received_count, 1U);
	zassert_equal(fm.rejected_count, 5U);
	zassert_equal(pqcp_edge_fragment_manager_audit(&fm), 0);
}

ZTEST(edge_security, test_fragment_output_capacity_expiry_and_slots)
{
	static struct pqcp_edge_fragment f;
	bool complete = true;
	size_t length = 0U;
	uint32_t expired = 0U;
	uint8_t other_id[PQCP_EDGE_MESSAGE_ID_BYTES];
	static uint8_t out2[1024];
	static uint8_t out3[1024];

	fragment_setup();
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload,
		sizeof(fg_payload), 0U, &f), 0);
	/* Output buffer smaller than total_length: nothing is recorded. */
	zassert_equal(pqcp_edge_fragment_accept(&fm, &f, fg_out, 599U, T0,
		1000U, &complete, &length), -ENOBUFS);
	zassert_equal(pqcp_edge_fragment_accept(&fm, &f, NULL, 1024U, T0,
		1000U, &complete, &length), -ENOBUFS);
	zassert_equal(pqcp_edge_fragment_accept(&fm, &f, fg_out,
		sizeof(fg_out), T0, 0U, &complete, &length), -ENOBUFS);
	zassert_false(fgstore[0].occupied);
	zassert_equal(pqcp_edge_fragment_manager_audit(&fm), 0);

	zassert_equal(pqcp_edge_fragment_accept(&fm, &f, fg_out,
		sizeof(fg_out), T0, 1000U, &complete, &length), 0);
	memset(other_id, 0x43, sizeof(other_id));
	{
		static struct pqcp_edge_fragment g;

		zassert_equal(pqcp_edge_message_fragment(other_id, fg_payload,
			sizeof(fg_payload), 0U, &g), 0);
		zassert_equal(pqcp_edge_fragment_accept(&fm, &g, out2,
			sizeof(out2), T0, 1000U, &complete, &length), 0);
		memset(other_id, 0x44, sizeof(other_id));
		zassert_equal(pqcp_edge_message_fragment(other_id, fg_payload,
			sizeof(fg_payload), 0U, &g), 0);
		/* All slots in use: fail closed. */
		zassert_equal(pqcp_edge_fragment_accept(&fm, &g, out3,
			sizeof(out3), T0, 1000U, &complete, &length), -ENOSPC);
	}

	/* An expired assembly refuses late fragments until reaped. */
	{
		static struct pqcp_edge_fragment f1;

		zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload,
			sizeof(fg_payload), 1U, &f1), 0);
		zassert_equal(pqcp_edge_fragment_accept(&fm, &f1, fg_out,
			sizeof(fg_out), T0 + 1000U, 1000U, &complete,
			&length), -ETIMEDOUT);
	}
	zassert_equal(pqcp_edge_fragment_expire(&fm, T0 + 999U, &expired), 0);
	zassert_equal(expired, 0U);
	zassert_equal(pqcp_edge_fragment_expire(&fm, T0 + 1000U, &expired),
		      0);
	zassert_equal(expired, 2U);
	zassert_false(fgstore[0].occupied);
	zassert_equal(pqcp_edge_fragment_manager_audit(&fm), 0);
}

ZTEST(edge_security, test_fragment_audit_detects_corruption)
{
	static struct pqcp_edge_fragment f;
	bool complete = true;
	size_t length = 0U;

	fragment_setup();
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload,
		sizeof(fg_payload), 0U, &f), 0);
	zassert_equal(pqcp_edge_fragment_accept(&fm, &f, fg_out,
		sizeof(fg_out), T0, 1000U, &complete, &length), 0);
	zassert_equal(pqcp_edge_fragment_manager_audit(&fm), 0);
	fgstore[0].received_count = 2U;
	zassert_equal(pqcp_edge_fragment_manager_audit(&fm), -EBADMSG);
	fgstore[0].received_count = 1U;
	fgstore[0].output = NULL;
	zassert_equal(pqcp_edge_fragment_manager_audit(&fm), -EBADMSG);
	fgstore[0].output = fg_out;
	fgstore[1] = fgstore[0];
	zassert_equal(pqcp_edge_fragment_manager_audit(&fm), -EEXIST);
}

ZTEST(edge_security, test_fragment_offset_must_match_index)
{
	static struct pqcp_edge_fragment f0;
	static struct pqcp_edge_fragment f1;
	bool complete = false;
	size_t length = 0U;
	size_t unwritten = 0U;
	int ret;

	fragment_setup();
	/* 300 bytes -> 2 fragments: [0,256) and [256,300). */
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload, 300U,
		0U, &f0), 0);
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload, 300U,
		1U, &f1), 0);
	/* Forge fragment 1 so that it overwrites offset 0 instead. */
	f1.offset = 0U;
	zassert_equal(pqcp_edge_fragment_accept(&fm, &f0, fg_out,
		sizeof(fg_out), T0, 1000U, &complete, &length), 0);
	ret = pqcp_edge_fragment_accept(&fm, &f1, fg_out, sizeof(fg_out),
		T0 + 1U, 1000U, &complete, &length);
	for (size_t i = 256U; i < 300U; ++i) {
		unwritten += (fg_out[i] == 0xee) ? 1U : 0U;
	}
	zassert_not_equal(ret, 0);
	zassert_false(complete);
	zassert_equal(unwritten, 44U);
	/* The genuine fragment 1 still completes the message. */
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload, 300U,
		1U, &f1), 0);
	zassert_equal(pqcp_edge_fragment_accept(&fm, &f1, fg_out,
		sizeof(fg_out), T0 + 2U, 1000U, &complete, &length), 0);
	zassert_true(complete);
	zassert_equal(length, 300U);
	zassert_mem_equal(fg_out, fg_payload, 300U);
	/* An offset beyond the slice boundary is refused as well. */
	zassert_equal(pqcp_edge_message_fragment(fg_id, fg_payload, 300U,
		0U, &f0), 0);
	f0.offset = 1U;
	zassert_not_equal(pqcp_edge_fragment_accept(&fm, &f0, fg_out,
		sizeof(fg_out), T0 + 3U, 1000U, &complete, &length), 0);
}

/* ------------------------------------------------------------------ */
/* Message ratchet                                                     */
/* ------------------------------------------------------------------ */

static void ratchet_pair(struct pqcp_edge_ratchet *a,
			 struct pqcp_edge_ratchet *b)
{
	uint8_t root[PQCP_EDGE_KEY_BYTES];

	edge_key(root, 0x21U);
	zassert_equal(pqcp_edge_ratchet_init(a, "peer-b", root, true, T0), 0);
	zassert_equal(pqcp_edge_ratchet_init(b, "peer-a", root, false, T0), 0);
}

ZTEST(edge_security, test_ratchet_rejects_invalid_arguments)
{
	struct pqcp_edge_ratchet r;
	struct pqcp_edge_ratchet raw;
	uint8_t root[PQCP_EDGE_KEY_BYTES];
	uint8_t zero[PQCP_EDGE_KEY_BYTES] = { 0 };
	uint8_t key[PQCP_EDGE_KEY_BYTES];
	uint64_t epoch = 0U;
	uint64_t sequence = 0U;
	char unterminated[PQCP_EDGE_ID_MAX_CHARS];

	edge_key(root, 3U);
	memset(unterminated, 'x', sizeof(unterminated));
	zassert_equal(pqcp_edge_ratchet_init(NULL, "p", root, true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_ratchet_init(&r, NULL, root, true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_ratchet_init(&r, "", root, true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_ratchet_init(&r, unterminated, root, true,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_ratchet_init(&r, "p", NULL, true, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_ratchet_init(&r, "p", zero, true, T0),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_ratchet_next_send(&raw, key, &epoch,
		&sequence), -EINVAL);
	zassert_equal(pqcp_edge_ratchet_receive(&raw, 1U, 1U, key), -EINVAL);
	zassert_equal(pqcp_edge_ratchet_rotate(&raw, root, 2U, T0), -EINVAL);
	/* Unlike its siblings the ratchet audit reports -EBADMSG here. */
	zassert_equal(pqcp_edge_ratchet_audit(&raw), -EBADMSG);
	zassert_equal(pqcp_edge_ratchet_audit(NULL), -EBADMSG);

	zassert_equal(pqcp_edge_ratchet_init(&r, "p", root, true, T0), 0);
	zassert_equal(pqcp_edge_ratchet_next_send(&r, NULL, &epoch,
		&sequence), -EINVAL);
	zassert_equal(pqcp_edge_ratchet_next_send(&r, key, NULL, &sequence),
		      -EINVAL);
	zassert_equal(pqcp_edge_ratchet_next_send(&r, key, &epoch, NULL),
		      -EINVAL);
	zassert_equal(pqcp_edge_ratchet_receive(&r, 0U, 1U, key), -EINVAL);
	zassert_equal(pqcp_edge_ratchet_receive(&r, 1U, 0U, key), -EINVAL);
	zassert_equal(pqcp_edge_ratchet_receive(&r, 1U, 1U, NULL), -EINVAL);
	zassert_equal(pqcp_edge_ratchet_rotate(&r, NULL, 2U, T0), -EINVAL);
	zassert_equal(pqcp_edge_ratchet_rotate(&r, zero, 2U, T0), -EINVAL);
	zassert_equal(pqcp_edge_ratchet_rotate(&r, root, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_ratchet_rotate(&r, root, 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_ratchet_audit(&r), 0);
}

ZTEST(edge_security, test_ratchet_send_receive_agreement)
{
	struct pqcp_edge_ratchet a;
	struct pqcp_edge_ratchet b;
	uint8_t ka1[PQCP_EDGE_KEY_BYTES];
	uint8_t ka2[PQCP_EDGE_KEY_BYTES];
	uint8_t kb1[PQCP_EDGE_KEY_BYTES];
	uint8_t kb2[PQCP_EDGE_KEY_BYTES];
	uint64_t epoch = 0U;
	uint64_t seq = 0U;

	ratchet_pair(&a, &b);
	zassert_equal(pqcp_edge_ratchet_next_send(&a, ka1, &epoch, &seq), 0);
	zassert_equal(epoch, 1U);
	zassert_equal(seq, 1U);
	zassert_equal(pqcp_edge_ratchet_next_send(&a, ka2, &epoch, &seq), 0);
	zassert_equal(seq, 2U);
	/* Each message gets a fresh key. */
	zassert_true(memcmp(ka1, ka2, sizeof(ka1)) != 0);

	zassert_equal(pqcp_edge_ratchet_receive(&b, 1U, 1U, kb1), 0);
	zassert_mem_equal(ka1, kb1, sizeof(ka1));
	zassert_equal(pqcp_edge_ratchet_receive(&b, 1U, 2U, kb2), 0);
	zassert_mem_equal(ka2, kb2, sizeof(ka2));

	/* The reverse direction uses an independent chain. */
	zassert_equal(pqcp_edge_ratchet_next_send(&b, kb1, &epoch, &seq), 0);
	zassert_true(memcmp(ka1, kb1, sizeof(ka1)) != 0);
	zassert_equal(pqcp_edge_ratchet_receive(&a, 1U, 1U, ka1), 0);
	zassert_mem_equal(ka1, kb1, sizeof(ka1));
	zassert_equal(pqcp_edge_ratchet_audit(&a), 0);
	zassert_equal(pqcp_edge_ratchet_audit(&b), 0);
}

ZTEST(edge_security, test_ratchet_replay_gap_and_epoch_rejection)
{
	struct pqcp_edge_ratchet a;
	struct pqcp_edge_ratchet b;
	struct pqcp_edge_ratchet snap;
	uint8_t key[PQCP_EDGE_KEY_BYTES];
	uint8_t ka[PQCP_EDGE_KEY_BYTES];
	uint64_t epoch = 0U;
	uint64_t seq = 0U;

	ratchet_pair(&a, &b);
	for (int i = 0; i < 3; ++i) {
		zassert_equal(pqcp_edge_ratchet_next_send(&a, ka, &epoch,
			&seq), 0);
	}
	/* Skipping ahead to 3 consumes 1 and 2 (forward secrecy). */
	zassert_equal(pqcp_edge_ratchet_receive(&b, 1U, 3U, key), 0);
	zassert_mem_equal(key, ka, sizeof(key));
	zassert_equal(b.skipped_messages, 2U);
	zassert_equal(b.receive_sequence, 3U);

	snap = b;
	/* Replays and skipped sequence numbers are refused, state intact. */
	zassert_equal(pqcp_edge_ratchet_receive(&b, 1U, 3U, key), -EALREADY);
	zassert_equal(pqcp_edge_ratchet_receive(&b, 1U, 2U, key), -EALREADY);
	/* Epoch from the future needs an explicit rotation first. */
	zassert_equal(pqcp_edge_ratchet_receive(&b, 2U, 1U, key), -ESTALE);
	/* A gap beyond the skip window is refused. */
	zassert_equal(pqcp_edge_ratchet_receive(&b, 1U, 3U + 65U, key),
		      -ERANGE);
	zassert_mem_equal(&b, &snap, sizeof(snap));
	zassert_equal(pqcp_edge_ratchet_receive(&b, 1U, 3U + 64U, key), 0);
}

ZTEST(edge_security, test_ratchet_rotation_failure_keeps_state)
{
	struct pqcp_edge_ratchet a;
	struct pqcp_edge_ratchet b;
	struct pqcp_edge_ratchet snap;
	uint8_t secret[PQCP_EDGE_KEY_BYTES];
	uint8_t key[PQCP_EDGE_KEY_BYTES];
	uint64_t epoch = 0U;
	uint64_t seq = 0U;

	ratchet_pair(&a, &b);
	edge_key(secret, 0x55U);
	zassert_equal(pqcp_edge_ratchet_next_send(&a, key, &epoch, &seq), 0);
	snap = a;
	zassert_equal(pqcp_edge_ratchet_rotate(&a, secret, 1U, T0 + 5U),
		      -EINVAL);
	zassert_mem_equal(&a, &snap, sizeof(snap));

	zassert_equal(pqcp_edge_ratchet_rotate(&a, secret, 7U, T0 + 5U), 0);
	zassert_equal(a.send_epoch, 7U);
	zassert_equal(a.receive_epoch, 7U);
	zassert_equal(a.send_sequence, 0U);
	zassert_equal(a.receive_sequence, 0U);
	zassert_equal(a.last_rotated_ms, T0 + 5U);
	zassert_true(memcmp(a.root_digest, snap.root_digest,
			    sizeof(snap.root_digest)) != 0);
	/* Messages from the previous epoch can no longer be accepted. */
	zassert_equal(pqcp_edge_ratchet_receive(&a, 1U, 5U, key), -EALREADY);
	zassert_equal(pqcp_edge_ratchet_audit(&a), 0);
	/* Epochs cannot be rolled back. */
	zassert_equal(pqcp_edge_ratchet_rotate(&a, secret, 7U, T0 + 6U),
		      -EINVAL);
	zassert_equal(pqcp_edge_ratchet_rotate(&a, secret, 3U, T0 + 6U),
		      -EINVAL);

	/* Audit catches a wiped chain key. */
	memset(a.send_chain_key, 0, sizeof(a.send_chain_key));
	zassert_equal(pqcp_edge_ratchet_audit(&a), -EBADMSG);
}

ZTEST(edge_security, test_ratchet_peers_interoperate_after_rotation)
{
	struct pqcp_edge_ratchet a;
	struct pqcp_edge_ratchet b;
	uint8_t secret[PQCP_EDGE_KEY_BYTES];
	uint8_t send_key[PQCP_EDGE_KEY_BYTES];
	uint8_t recv_key[PQCP_EDGE_KEY_BYTES];
	uint64_t epoch = 0U;
	uint64_t seq = 0U;
	int ret;

	ratchet_pair(&a, &b);
	edge_key(secret, 0x55U);
	zassert_equal(pqcp_edge_ratchet_rotate(&a, secret, 2U, T0 + 5U), 0);
	zassert_equal(pqcp_edge_ratchet_rotate(&b, secret, 2U, T0 + 5U), 0);
	zassert_equal(pqcp_edge_ratchet_next_send(&a, send_key, &epoch,
		&seq), 0);
	ret = pqcp_edge_ratchet_receive(&b, epoch, seq, recv_key);
	zassert_equal(ret, 0);
	zassert_mem_equal(send_key, recv_key, sizeof(send_key));
	/* And the reverse direction: responder send == initiator receive. */
	zassert_equal(pqcp_edge_ratchet_next_send(&b, send_key, &epoch,
		&seq), 0);
	zassert_equal(pqcp_edge_ratchet_receive(&a, epoch, seq, recv_key), 0);
	zassert_mem_equal(send_key, recv_key, sizeof(send_key));
}

/* ------------------------------------------------------------------ */
/* Topic registry                                                      */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_topic tpstore[2];
static struct pqcp_edge_subscription substore[2];
static struct pqcp_edge_topic_registry treg;

static void topic_setup(void)
{
	zassert_equal(pqcp_edge_topic_registry_init(
		&treg, tpstore, ARRAY_SIZE(tpstore),
		substore, ARRAY_SIZE(substore)), 0);
}

static void make_topic(struct pqcp_edge_topic *t, const char *name,
		       uint64_t publish_caps, uint64_t subscribe_caps)
{
	memset(t, 0, sizeof(*t));
	SETSTR(t->topic, name);
	SETSTR(t->owner_id, "owner-1");
	t->publish_capabilities = publish_caps;
	t->subscribe_capabilities = subscribe_caps;
	t->maximum_payload = 128U;
	t->maximum_subscribers = 2U;
	t->encrypted = true;
}

static void make_user(struct pqcp_edge_principal *p, const char *id,
		      uint64_t caps)
{
	edge_make_principal(p, id, caps, PQCP_EDGE_TRUST_ATTESTED, 900000U);
	p->schema_version = PQCP_EDGE_SCHEMA_VERSION;
}

ZTEST(edge_security, test_topic_registry_rejects_invalid_arguments)
{
	static struct pqcp_edge_topic_registry raw;
	struct pqcp_edge_topic t;
	struct pqcp_edge_principal p;
	struct pqcp_edge_subscription *sub = NULL;
	uint32_t expired = 0U;

	zassert_equal(pqcp_edge_topic_registry_init(NULL, tpstore, 2U,
		substore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_topic_registry_init(&treg, NULL, 2U,
		substore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_topic_registry_init(&treg, tpstore, 0U,
		substore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_topic_registry_init(&treg, tpstore, 2U,
		NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_topic_registry_init(&treg, tpstore, 2U,
		substore, 0U), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_topic(&t, "t1", 1U, 1U);
	make_user(&p, "u1", 1U);
	zassert_equal(pqcp_edge_topic_create(&raw, &t), -EINVAL);
	zassert_equal(pqcp_edge_topic_remove(&raw, "t1"), -EINVAL);
	zassert_equal(pqcp_edge_topic_authorize_publish(&raw, "t1", &p, 1U),
		      -EINVAL);
	zassert_equal(pqcp_edge_topic_subscribe(&raw, "t1", &p, T0, 10U, 1U,
		&sub), -EINVAL);
	zassert_equal(pqcp_edge_topic_unsubscribe(&raw, 1U), -EINVAL);
	zassert_equal(pqcp_edge_topic_acknowledge(&raw, 1U, 1U), -EINVAL);
	zassert_equal(pqcp_edge_topic_tick(&raw, T0, &expired), -EINVAL);
	zassert_equal(pqcp_edge_topic_registry_audit(&raw), -EINVAL);

	topic_setup();
	zassert_equal(pqcp_edge_topic_create(&treg, NULL), -EINVAL);
	t.topic[0] = '\0';
	zassert_equal(pqcp_edge_topic_create(&treg, &t), -EINVAL);
	make_topic(&t, "t1", 1U, 1U);
	t.owner_id[0] = '\0';
	zassert_equal(pqcp_edge_topic_create(&treg, &t), -EINVAL);
	make_topic(&t, "t1", 1U, 1U);
	t.maximum_payload = 0U;
	zassert_equal(pqcp_edge_topic_create(&treg, &t), -EINVAL);
	t.maximum_payload = PQCP_EDGE_MESSAGE_PAYLOAD_MAX_BYTES + 1U;
	zassert_equal(pqcp_edge_topic_create(&treg, &t), -EINVAL);
	make_topic(&t, "t1", 1U, 1U);
	t.maximum_subscribers = 0U;
	zassert_equal(pqcp_edge_topic_create(&treg, &t), -EINVAL);
	zassert_false(tpstore[0].occupied);

	zassert_equal(pqcp_edge_topic_remove(&treg, NULL), -EINVAL);
	zassert_equal(pqcp_edge_topic_remove(&treg, "t1"), -ENOENT);
	zassert_equal(pqcp_edge_topic_authorize_publish(&treg, NULL, &p, 1U),
		      -EINVAL);
	zassert_equal(pqcp_edge_topic_authorize_publish(&treg, "t1", NULL,
		1U), -EINVAL);
	zassert_equal(pqcp_edge_topic_authorize_publish(&treg, "t1", &p, 0U),
		      -EINVAL);
	zassert_equal(pqcp_edge_topic_authorize_publish(&treg, "t1", &p, 1U),
		      -ENOENT);
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &p, T0, 10U, 1U,
		NULL), -EINVAL);
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &p, T0, 0U, 1U,
		&sub), -EINVAL);
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &p, T0, 10U, 0U,
		&sub), -EINVAL);
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &p, T0, 10U, 1U,
		&sub), -ENOENT);
	zassert_is_null(sub);
	zassert_equal(pqcp_edge_topic_unsubscribe(&treg, 0U), -EINVAL);
	zassert_equal(pqcp_edge_topic_unsubscribe(&treg, 9U), -ENOENT);
	zassert_equal(pqcp_edge_topic_acknowledge(&treg, 0U, 1U), -EINVAL);
	zassert_equal(pqcp_edge_topic_acknowledge(&treg, 1U, 0U), -EINVAL);
	zassert_equal(pqcp_edge_topic_acknowledge(&treg, 9U, 1U), -ENOENT);
	zassert_equal(pqcp_edge_topic_tick(&treg, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_topic_registry_audit(&treg), 0);
}

ZTEST(edge_security, test_topic_create_update_and_remove_rules)
{
	struct pqcp_edge_topic t;
	struct pqcp_edge_principal p;
	struct pqcp_edge_subscription *sub = NULL;
	struct pqcp_edge_topic snap[2];

	topic_setup();
	make_user(&p, "u1", 1U);
	make_topic(&t, "t1", 1U, 1U);
	zassert_equal(pqcp_edge_topic_create(&treg, &t), 0);
	zassert_true(tpstore[0].generation != 0U);
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &p, T0, 1000U,
		4U, &sub), 0);
	zassert_equal(pqcp_edge_topic_authorize_publish(&treg, "t1", &p,
		10U), 0);

	/* Only the owner may update, and never below live subscribers. */
	SETSTR(t.owner_id, "intruder");
	zassert_equal(pqcp_edge_topic_create(&treg, &t), -EACCES);
	make_topic(&t, "t1", 1U, 1U);
	t.maximum_subscribers = 1U;
	zassert_equal(pqcp_edge_topic_create(&treg, &t), 0);
	zassert_equal(tpstore[0].maximum_subscribers, 1U);
	zassert_equal(tpstore[0].active_subscribers, 1U);
	zassert_equal(tpstore[0].published_count, 1U);
	/* Dropping the subscriber limit under the current count is refused. */
	zassert_equal(pqcp_edge_topic_registry_audit(&treg), 0);

	/* A topic with live subscribers cannot be removed. */
	zassert_equal(pqcp_edge_topic_remove(&treg, "t1"), -EBUSY);
	zassert_true(tpstore[0].occupied);
	zassert_equal(pqcp_edge_topic_unsubscribe(&treg, sub->subscription_id),
		      0);
	zassert_equal(pqcp_edge_topic_remove(&treg, "t1"), 0);
	zassert_false(tpstore[0].occupied);

	/* Capacity exhaustion leaves existing topics intact. */
	make_topic(&t, "a", 1U, 1U);
	zassert_equal(pqcp_edge_topic_create(&treg, &t), 0);
	make_topic(&t, "b", 1U, 1U);
	zassert_equal(pqcp_edge_topic_create(&treg, &t), 0);
	memcpy(snap, tpstore, sizeof(snap));
	make_topic(&t, "c", 1U, 1U);
	zassert_equal(pqcp_edge_topic_create(&treg, &t), -ENOSPC);
	zassert_mem_equal(tpstore, snap, sizeof(snap));
}

ZTEST(edge_security, test_topic_publish_authorization_is_capability_scoped)
{
	struct pqcp_edge_topic t;
	struct pqcp_edge_principal p;

	topic_setup();
	make_topic(&t, "t1", 0x6U, 1U);
	zassert_equal(pqcp_edge_topic_create(&treg, &t), 0);

	make_user(&p, "u1", 0x2U);
	zassert_equal(pqcp_edge_topic_authorize_publish(&treg, "t1", &p,
		10U), -EACCES);
	p.capabilities = 0x6U;
	zassert_equal(pqcp_edge_topic_authorize_publish(&treg, "t1", &p,
		129U), -E2BIG);
	zassert_equal(tpstore[0].published_count, 0U);
	p.state = PQCP_EDGE_PRINCIPAL_QUARANTINED;
	zassert_equal(pqcp_edge_topic_authorize_publish(&treg, "t1", &p,
		10U), -EACCES);
	p.state = PQCP_EDGE_PRINCIPAL_REVOKED;
	zassert_equal(pqcp_edge_topic_authorize_publish(&treg, "t1", &p,
		10U), -EACCES);
	p.state = PQCP_EDGE_PRINCIPAL_ACTIVE;
	zassert_equal(pqcp_edge_topic_authorize_publish(&treg, "t1", &p,
		128U), 0);
	zassert_equal(tpstore[0].published_count, 1U);
}

ZTEST(edge_security, test_topic_subscription_lifecycle_and_quota)
{
	struct pqcp_edge_topic t;
	struct pqcp_edge_principal u1;
	struct pqcp_edge_principal u2;
	struct pqcp_edge_principal u3;
	struct pqcp_edge_subscription *s1 = NULL;
	struct pqcp_edge_subscription *s2 = NULL;
	struct pqcp_edge_subscription *dup = NULL;
	struct pqcp_edge_subscription *none = (void *)0x1;
	uint32_t expired = 0U;
	uint64_t s2_id;

	topic_setup();
	make_topic(&t, "t1", 1U, 0x4U);
	t.maximum_subscribers = 2U;
	zassert_equal(pqcp_edge_topic_create(&treg, &t), 0);
	make_user(&u1, "u1", 0x4U);
	make_user(&u2, "u2", 0x4U);
	make_user(&u3, "u3", 0x4U);

	/* Lacking the subscribe capability is refused. */
	{
		struct pqcp_edge_principal weak;

		make_user(&weak, "weak", 0x1U);
		zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &weak,
			T0, 1000U, 2U, &none), -EACCES);
		zassert_is_null(none);
	}
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &u1, T0, 1000U,
		2U, &s1), 0);
	zassert_equal(s1->expires_at_ms, T0 + 1000U);
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &u2, T0, 2000U,
		2U, &s2), 0);
	/* Re-subscribing returns the live subscription and is flagged. */
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &u1, T0 + 1U,
		1000U, 2U, &dup), -EALREADY);
	zassert_equal(dup, s1);
	zassert_equal(tpstore[0].active_subscribers, 2U);
	/* Subscriber quota (and the subscription table) is full. */
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &u3, T0, 1000U,
		2U, &none), -EDQUOT);
	zassert_is_null(none);

	/* Acknowledgements are strictly monotonic per subscription. */
	zassert_equal(pqcp_edge_topic_acknowledge(&treg, s1->subscription_id,
		5U), 0);
	zassert_equal(s1->last_acknowledged_sequence, 5U);
	zassert_equal(pqcp_edge_topic_acknowledge(&treg, s1->subscription_id,
		5U), -ESTALE);
	zassert_equal(pqcp_edge_topic_acknowledge(&treg, s1->subscription_id,
		4U), -ESTALE);
	zassert_equal(tpstore[0].delivered_count, 1U);

	zassert_equal(pqcp_edge_topic_tick(&treg, T0 + 999U, &expired), 0);
	zassert_equal(expired, 0U);
	zassert_equal(pqcp_edge_topic_tick(&treg, T0 + 1000U, &expired), 0);
	zassert_equal(expired, 1U);
	zassert_equal(tpstore[0].active_subscribers, 1U);
	zassert_false(substore[0].occupied);
	zassert_equal(pqcp_edge_topic_registry_audit(&treg), 0);

	/* The freed quota is immediately reusable. */
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &u3, T0 + 1001U,
		1000U, 2U, &none), 0);
	s2_id = s2->subscription_id;
	zassert_equal(pqcp_edge_topic_unsubscribe(&treg, s2_id), 0);
	zassert_equal(tpstore[0].active_subscribers, 1U);
	zassert_equal(pqcp_edge_topic_unsubscribe(&treg, s2_id), -ENOENT);
	zassert_equal(pqcp_edge_topic_registry_audit(&treg), 0);
}

ZTEST(edge_security, test_topic_resubscribe_after_expiry_keeps_counts)
{
	struct pqcp_edge_topic t;
	struct pqcp_edge_principal u1;
	struct pqcp_edge_subscription *s = NULL;
	int ret;

	topic_setup();
	make_topic(&t, "t1", 1U, 1U);
	zassert_equal(pqcp_edge_topic_create(&treg, &t), 0);
	make_user(&u1, "u1", 1U);
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &u1, T0, 100U,
		2U, &s), 0);
	/* The subscription lapses; no tick has run yet. */
	zassert_equal(pqcp_edge_topic_subscribe(&treg, "t1", &u1, T0 + 200U,
		100U, 2U, &s), 0);

	ret = pqcp_edge_topic_registry_audit(&treg);
	zassert_equal(ret, 0);
	zassert_equal(tpstore[0].active_subscribers, 1U);
	zassert_equal(pqcp_edge_topic_unsubscribe(&treg,
		s->subscription_id), 0);
	zassert_equal(tpstore[0].active_subscribers, 0U);
	zassert_equal(pqcp_edge_topic_registry_audit(&treg), 0);
}

/* ------------------------------------------------------------------ */
/* Group manager                                                       */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_group gstore[2];
static struct pqcp_edge_group_manager gm;

static void group_setup(void)
{
	zassert_equal(pqcp_edge_group_manager_init(
		&gm, gstore, ARRAY_SIZE(gstore)), 0);
}

ZTEST(edge_security, test_group_manager_rejects_invalid_arguments)
{
	static struct pqcp_edge_group_manager raw;
	uint8_t key[PQCP_EDGE_KEY_BYTES];
	uint8_t zero[PQCP_EDGE_KEY_BYTES] = { 0 };

	edge_key(key, 9U);
	zassert_equal(pqcp_edge_group_manager_init(NULL, gstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_group_manager_init(&gm, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_group_manager_init(&gm, gstore, 0U), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_group_create(&raw, "g", "o", key, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_group_add_member(&raw, "g", "m", 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_group_remove_member(&raw, "g", "m", T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_group_rotate(&raw, "g", key, T0), -EINVAL);
	zassert_equal(pqcp_edge_group_authorize(&raw, "g", "m", 1U),
		      -EINVAL);
	zassert_equal(pqcp_edge_group_manager_audit(&raw), -EINVAL);

	group_setup();
	zassert_equal(pqcp_edge_group_create(&gm, NULL, "o", key, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_group_create(&gm, "g", NULL, key, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_group_create(&gm, "g", "o", NULL, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_group_create(&gm, "g", "o", zero, T0),
		      -EINVAL);
	zassert_false(gstore[0].occupied);
	zassert_equal(pqcp_edge_group_add_member(&gm, NULL, "m", 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_group_add_member(&gm, "g", "m", 0U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_group_add_member(&gm, "g", "m", 1U, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_group_remove_member(&gm, "g", NULL, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_group_remove_member(&gm, "g", "m", T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_group_rotate(&gm, NULL, key, T0), -EINVAL);
	zassert_equal(pqcp_edge_group_rotate(&gm, "g", zero, T0), -EINVAL);
	zassert_equal(pqcp_edge_group_rotate(&gm, "g", key, T0), -ENOENT);
	zassert_equal(pqcp_edge_group_authorize(&gm, "g", "m", 0U), -EINVAL);
	zassert_equal(pqcp_edge_group_authorize(&gm, "g", "m", 1U), -ENOENT);
	zassert_equal(pqcp_edge_group_manager_audit(&gm), 0);
}

ZTEST(edge_security, test_group_membership_and_authorization)
{
	uint8_t key[PQCP_EDGE_KEY_BYTES];
	struct pqcp_edge_group snap;

	edge_key(key, 9U);
	group_setup();
	zassert_equal(pqcp_edge_group_create(&gm, "g", "owner", key, T0), 0);
	zassert_equal(pqcp_edge_group_create(&gm, "g", "owner", key, T0),
		      -EEXIST);
	zassert_equal(gstore[0].epoch, 1U);
	zassert_equal(gstore[0].member_count, 1U);
	zassert_equal(pqcp_edge_group_authorize(&gm, "g", "owner", 0xffU), 0);

	zassert_equal(pqcp_edge_group_add_member(&gm, "g", "m1", 0x3U,
		T0 + 1U), 0);
	zassert_equal(pqcp_edge_group_add_member(&gm, "g", "m1", 0x3U,
		T0 + 2U), -EALREADY);
	zassert_equal(gstore[0].member_count, 2U);
	zassert_equal(pqcp_edge_group_authorize(&gm, "g", "m1", 0x1U), 0);
	zassert_equal(pqcp_edge_group_authorize(&gm, "g", "m1", 0x4U),
		      -EACCES);
	zassert_equal(pqcp_edge_group_authorize(&gm, "g", "stranger", 0x1U),
		      -EACCES);

	/* The owner cannot be removed; unknown members are not found. */
	snap = gstore[0];
	zassert_equal(pqcp_edge_group_remove_member(&gm, "g", "owner",
		T0 + 3U), -EPERM);
	zassert_equal(pqcp_edge_group_remove_member(&gm, "g", "ghost",
		T0 + 3U), -ENOENT);
	zassert_mem_equal(&gstore[0], &snap, sizeof(snap));

	zassert_equal(pqcp_edge_group_remove_member(&gm, "g", "m1", T0 + 4U),
		      0);
	zassert_equal(gstore[0].member_count, 1U);
	zassert_equal(pqcp_edge_group_authorize(&gm, "g", "m1", 0x1U),
		      -EACCES);
	zassert_equal(gm.membership_changes, 2U);
	zassert_equal(pqcp_edge_group_manager_audit(&gm), 0);
}

ZTEST(edge_security, test_group_member_capacity_and_rotation)
{
	uint8_t key[PQCP_EDGE_KEY_BYTES];
	uint8_t key2[PQCP_EDGE_KEY_BYTES];
	uint8_t old_digest[PQCP_EDGE_DIGEST_BYTES];
	char name[16];

	edge_key(key, 9U);
	edge_key(key2, 10U);
	group_setup();
	zassert_equal(pqcp_edge_group_create(&gm, "g", "owner", key, T0), 0);
	zassert_equal(pqcp_edge_group_create(&gm, "h", "owner", key, T0), 0);
	zassert_equal(pqcp_edge_group_create(&gm, "i", "owner", key, T0),
		      -ENOSPC);

	for (uint32_t i = 1U; i < PQCP_EDGE_MAX_GROUP_MEMBERS; ++i) {
		snprintf(name, sizeof(name), "m%u", i);
		zassert_equal(pqcp_edge_group_add_member(&gm, "g", name, 1U,
			T0), 0);
	}
	zassert_equal(gstore[0].member_count, PQCP_EDGE_MAX_GROUP_MEMBERS);
	zassert_equal(pqcp_edge_group_add_member(&gm, "g", "overflow", 1U,
		T0), -ENOSPC);
	zassert_equal(gstore[0].member_count, PQCP_EDGE_MAX_GROUP_MEMBERS);
	zassert_equal(pqcp_edge_group_authorize(&gm, "g", "m1", 1U), 0);
	zassert_equal(pqcp_edge_group_manager_audit(&gm), 0);

	memcpy(old_digest, gstore[0].key_digest, sizeof(old_digest));
	zassert_equal(pqcp_edge_group_rotate(&gm, "g", key2, T0 + 10U), 0);
	zassert_equal(gstore[0].epoch, 2U);
	zassert_equal(gstore[0].rotated_at_ms, T0 + 10U);
	zassert_true(memcmp(old_digest, gstore[0].key_digest,
			    sizeof(old_digest)) != 0);
	/* The other group is unaffected. */
	zassert_equal(gstore[1].epoch, 1U);

	/* Audit catches tampering. */
	gstore[0].member_count = 3U;
	zassert_equal(pqcp_edge_group_manager_audit(&gm), -EBADMSG);
	gstore[0].member_count = PQCP_EDGE_MAX_GROUP_MEMBERS;
	memset(gstore[0].key_digest, 0, sizeof(gstore[0].key_digest));
	zassert_equal(pqcp_edge_group_manager_audit(&gm), -EBADMSG);
}

ZTEST(edge_security, test_group_rotation_requires_fresh_key_material)
{
	uint8_t key[PQCP_EDGE_KEY_BYTES];
	int ret;

	edge_key(key, 9U);
	group_setup();
	zassert_equal(pqcp_edge_group_create(&gm, "g", "owner", key, T0), 0);
	zassert_equal(pqcp_edge_group_add_member(&gm, "g", "m1", 1U, T0), 0);
	zassert_equal(pqcp_edge_group_remove_member(&gm, "g", "m1", T0 + 1U),
		      0);

	/* Rotating with the very same key must not advance the epoch: the
	 * evicted member still holds that key.
	 */
	ret = pqcp_edge_group_rotate(&gm, "g", key, T0 + 2U);
	zassert_equal(ret, -EALREADY);
	zassert_equal(gstore[0].epoch, 1U);
	zassert_equal(pqcp_edge_group_manager_audit(&gm), 0);
	/* A genuinely new key still rotates. */
	edge_key(key, 10U);
	zassert_equal(pqcp_edge_group_rotate(&gm, "g", key, T0 + 3U), 0);
	zassert_equal(gstore[0].epoch, 2U);
	/* ...and the new key cannot be replayed either. */
	zassert_equal(pqcp_edge_group_rotate(&gm, "g", key, T0 + 4U),
		      -EALREADY);
	zassert_equal(gstore[0].epoch, 2U);
}

/* ------------------------------------------------------------------ */
/* Delivery manager                                                    */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_delivery dvstore[2];
static struct pqcp_edge_delivery_manager dm;

static void delivery_setup(void)
{
	zassert_equal(pqcp_edge_delivery_manager_init(
		&dm, dvstore, ARRAY_SIZE(dvstore)), 0);
}

ZTEST(edge_security, test_delivery_rejects_invalid_arguments)
{
	static struct pqcp_edge_delivery_manager raw;
	uint8_t id[PQCP_EDGE_MESSAGE_ID_BYTES];
	uint8_t zero[PQCP_EDGE_MESSAGE_ID_BYTES] = { 0 };
	struct pqcp_edge_delivery *d = (void *)0x1;
	uint32_t changed = 0U;

	memset(id, 0x11, sizeof(id));
	zassert_equal(pqcp_edge_delivery_manager_init(NULL, dvstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_delivery_manager_init(&dm, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_delivery_manager_init(&dm, dvstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_delivery_dispatch(&raw, id, 1U, T0, T0 + 10U,
		1U, &d), -EINVAL);
	zassert_equal(pqcp_edge_delivery_complete(&raw, 1U, 0, T0), -EINVAL);
	zassert_equal(pqcp_edge_delivery_retry(&raw, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_delivery_tick(&raw, T0, &changed), -EINVAL);
	zassert_equal(pqcp_edge_delivery_manager_audit(&raw), -EINVAL);

	delivery_setup();
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, NULL, 1U, T0, T0 + 10U,
		1U, &d), -EINVAL);
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, zero, 1U, T0,
		T0 + 10U, 1U, &d), -EINVAL);
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 0U, T0, T0 + 10U,
		1U, &d), -EINVAL);
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 1U, T0, T0, 1U,
		&d), -EINVAL);
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 1U, T0, T0 + 10U,
		0U, &d), -EINVAL);
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 1U, T0, T0 + 10U,
		1U, NULL), -EINVAL);
	zassert_equal(dm.dispatch_count, 0U);
	zassert_equal(pqcp_edge_delivery_complete(&dm, 0U, 0, T0), -EINVAL);
	zassert_equal(pqcp_edge_delivery_complete(&dm, 9U, 0, T0), -ENOENT);
	zassert_equal(pqcp_edge_delivery_retry(&dm, 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_delivery_retry(&dm, 9U, T0), -ENOENT);
	zassert_equal(pqcp_edge_delivery_tick(&dm, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_delivery_manager_audit(&dm), 0);
}

ZTEST(edge_security, test_delivery_retry_budget_and_dead_letter)
{
	uint8_t id[PQCP_EDGE_MESSAGE_ID_BYTES];
	struct pqcp_edge_delivery *d = NULL;
	uint32_t changed = 0U;

	memset(id, 0x11, sizeof(id));
	delivery_setup();
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 5U, T0,
		T0 + 100000U, 3U, &d), 0);
	zassert_equal(d->state, PQCP_EDGE_MESSAGE_IN_FLIGHT);
	zassert_equal(d->attempts, 1U);

	/* Failure schedules an exponential retry (100 ms, then 200 ms). */
	zassert_equal(pqcp_edge_delivery_complete(&dm, d->delivery_id, -EIO,
		T0 + 10U), 0);
	zassert_equal(d->state, PQCP_EDGE_MESSAGE_RETRY_WAIT);
	zassert_equal(d->retry_at_ms, T0 + 110U);
	zassert_equal(pqcp_edge_delivery_tick(&dm, T0 + 109U, &changed), 0);
	zassert_equal(changed, 0U);
	zassert_equal(pqcp_edge_delivery_tick(&dm, T0 + 110U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(d->state, PQCP_EDGE_MESSAGE_IN_FLIGHT);
	zassert_equal(d->attempts, 2U);
	zassert_equal(pqcp_edge_delivery_complete(&dm, d->delivery_id, -EIO,
		T0 + 120U), 0);
	zassert_equal(d->retry_at_ms, T0 + 320U);
	/* An explicit retry time can be moved while waiting. */
	zassert_equal(pqcp_edge_delivery_retry(&dm, d->delivery_id,
		T0 + 500U), 0);
	zassert_equal(d->retry_at_ms, T0 + 500U);
	zassert_equal(pqcp_edge_delivery_tick(&dm, T0 + 500U, &changed), 0);
	zassert_equal(d->attempts, 3U);
	/* Final failed attempt: dead letter, no further retries. */
	zassert_equal(pqcp_edge_delivery_complete(&dm, d->delivery_id, -EIO,
		T0 + 510U), 0);
	zassert_equal(d->state, PQCP_EDGE_MESSAGE_DEAD_LETTER);
	zassert_equal(dm.failure_count, 1U);
	zassert_equal(pqcp_edge_delivery_complete(&dm, d->delivery_id, 0,
		T0 + 520U), -EALREADY);
	zassert_equal(pqcp_edge_delivery_retry(&dm, d->delivery_id,
		T0 + 600U), -EALREADY);
	zassert_equal(d->state, PQCP_EDGE_MESSAGE_DEAD_LETTER);
	zassert_equal(pqcp_edge_delivery_manager_audit(&dm), 0);
}

ZTEST(edge_security, test_delivery_deadlines_and_success)
{
	uint8_t id[PQCP_EDGE_MESSAGE_ID_BYTES];
	struct pqcp_edge_delivery *d = NULL;
	struct pqcp_edge_delivery *d2 = NULL;
	uint32_t changed = 0U;

	memset(id, 0x22, sizeof(id));
	delivery_setup();
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 5U, T0, T0 + 1000U,
		3U, &d), 0);
	zassert_equal(pqcp_edge_delivery_complete(&dm, d->delivery_id, 0,
		T0 + 5U), 0);
	zassert_equal(d->state, PQCP_EDGE_MESSAGE_ACKNOWLEDGED);
	zassert_equal(dm.success_count, 1U);

	/* A failure reported after the deadline expires the delivery. */
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 5U, T0, T0 + 1000U,
		3U, &d2), 0);
	zassert_equal(pqcp_edge_delivery_complete(&dm, d2->delivery_id, -EIO,
		T0 + 1000U), 0);
	zassert_equal(d2->state, PQCP_EDGE_MESSAGE_EXPIRED);

	/* Retry scheduled beyond the deadline expires it. */
	{
		struct pqcp_edge_delivery *d3 = NULL;

		zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 6U, T0 +
			2000U, T0 + 3000U, 3U, &d3), 0);
		zassert_equal(pqcp_edge_delivery_complete(&dm, d3->delivery_id,
			-EIO, T0 + 2010U), 0);
		zassert_equal(pqcp_edge_delivery_retry(&dm, d3->delivery_id,
			T0 + 3000U), -ETIMEDOUT);
		zassert_equal(d3->state, PQCP_EDGE_MESSAGE_EXPIRED);
	}

	/* Tick expires in-flight work that missed its deadline. */
	{
		struct pqcp_edge_delivery *d4 = NULL;

		zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 7U, T0 +
			5000U, T0 + 6000U, 3U, &d4), 0);
		zassert_equal(pqcp_edge_delivery_tick(&dm, T0 + 6000U,
			&changed), 0);
		zassert_equal(changed, 1U);
		zassert_equal(d4->state, PQCP_EDGE_MESSAGE_EXPIRED);
	}
	zassert_equal(pqcp_edge_delivery_manager_audit(&dm), 0);
}

ZTEST(edge_security, test_delivery_capacity_recycling_and_audit)
{
	uint8_t id[PQCP_EDGE_MESSAGE_ID_BYTES];
	struct pqcp_edge_delivery *d1 = NULL;
	struct pqcp_edge_delivery *d2 = NULL;
	struct pqcp_edge_delivery *d3 = (void *)0x1;
	struct pqcp_edge_delivery snap[2];

	memset(id, 0x33, sizeof(id));
	delivery_setup();
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 1U, T0, T0 + 1000U,
		2U, &d1), 0);
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 2U, T0 + 1U,
		T0 + 1000U, 2U, &d2), 0);
	memcpy(snap, dvstore, sizeof(snap));
	/* In-flight work is never evicted for a new dispatch. */
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 3U, T0 + 2U,
		T0 + 1000U, 2U, &d3), -ENOSPC);
	zassert_is_null(d3);
	zassert_mem_equal(dvstore, snap, sizeof(snap));

	zassert_equal(pqcp_edge_delivery_complete(&dm, d1->delivery_id, 0,
		T0 + 3U), 0);
	zassert_equal(pqcp_edge_delivery_dispatch(&dm, id, 3U, T0 + 4U,
		T0 + 1000U, 2U, &d3), 0);
	zassert_equal(d3, d1);
	zassert_true(d3->delivery_id > d2->delivery_id);

	d2->attempts = d2->maximum_attempts + 1U;
	zassert_equal(pqcp_edge_delivery_manager_audit(&dm), -EBADMSG);
	d2->attempts = 1U;
	dvstore[0].delivery_id = dvstore[1].delivery_id;
	zassert_equal(pqcp_edge_delivery_manager_audit(&dm), -EEXIST);
}
