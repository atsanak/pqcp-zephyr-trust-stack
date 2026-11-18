/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Durable fixed-capacity secure message queue with exact idempotency.
 */

#include <errno.h>
#include <string.h>

#include "edge_security_internal.h"

static bool priority_valid(
	enum pqcp_edge_message_priority priority)
{
	return priority >= PQCP_EDGE_MESSAGE_BACKGROUND &&
	       priority <= PQCP_EDGE_MESSAGE_CRITICAL;
}

static bool guarantee_valid(
	enum pqcp_edge_delivery_guarantee guarantee)
{
	return guarantee >=
		       PQCP_EDGE_DELIVERY_AT_MOST_ONCE &&
	       guarantee <=
		       PQCP_EDGE_DELIVERY_EFFECTIVELY_ONCE;
}

static bool state_valid(
	enum pqcp_edge_message_state state)
{
	return state >= PQCP_EDGE_MESSAGE_EMPTY &&
	       state <= PQCP_EDGE_MESSAGE_CANCELLED;
}

static int message_index(
	const struct pqcp_edge_message_queue *queue,
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES])
{
	for (size_t index = 0U;
	     index < queue->capacity; ++index) {
		if (queue->messages[index].occupied &&
		    pqcp_edge_internal_equal(
			    queue->messages[index].message_id,
			    message_id,
			    PQCP_EDGE_MESSAGE_ID_BYTES)) {
			return (int)index;
		}
	}
	return -ENOENT;
}

static bool terminal_state(
	enum pqcp_edge_message_state state)
{
	return state == PQCP_EDGE_MESSAGE_ACKNOWLEDGED ||
	       state == PQCP_EDGE_MESSAGE_DEAD_LETTER ||
	       state == PQCP_EDGE_MESSAGE_EXPIRED ||
	       state == PQCP_EDGE_MESSAGE_CANCELLED;
}

static int free_message_index(
	const struct pqcp_edge_message_queue *queue)
{
	int recyclable = -1;
	uint64_t oldest_created = UINT64_MAX;

	for (size_t index = 0U;
	     index < queue->capacity; ++index) {
		const struct pqcp_edge_message *message =
			&queue->messages[index];

		if (!message->occupied) {
			return (int)index;
		}
		if (terminal_state(message->state) &&
		    message->created_at_ms < oldest_created) {
			oldest_created = message->created_at_ms;
			recyclable = (int)index;
		}
	}
	return recyclable >= 0 ? recyclable : -ENOSPC;
}

static bool message_shape_valid(
	const struct pqcp_edge_message *message)
{
	return message != NULL &&
	       !pqcp_edge_internal_all_zero(
		       message->message_id,
		       sizeof(message->message_id)) &&
	       pqcp_edge_internal_text_valid(
		       message->producer_id,
		       sizeof(message->producer_id)) &&
	       pqcp_edge_internal_text_valid(
		       message->consumer_id,
		       sizeof(message->consumer_id)) &&
	       pqcp_edge_internal_text_valid(
		       message->topic,
		       sizeof(message->topic)) &&
	       message->producer_epoch != 0U &&
	       message->sequence != 0U &&
	       message->payload_length != 0U &&
	       message->payload_length <=
		       sizeof(message->payload) &&
	       message->maximum_attempts != 0U &&
	       priority_valid(message->priority) &&
	       guarantee_valid(message->guarantee) &&
	       state_valid(message->state);
}

static int payload_digest(
	const struct pqcp_edge_message *message,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	return pqcp_edge_internal_sha256(
		message->payload,
		message->payload_length,
		output);
}

static int message_digest(
	const struct pqcp_edge_message *message,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES])
{
	uint8_t numeric[72];
	const uint8_t *parts[7];
	size_t lengths[7];
	size_t offset = 0U;

	if (!message_shape_valid(message) ||
	    output == NULL) {
		return -EINVAL;
	}
	pqcp_edge_internal_write_u32(
		numeric + offset, message->schema_version);
	offset += 4U;
	pqcp_edge_internal_write_u64(
		numeric + offset, message->producer_epoch);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, message->sequence);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, message->created_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, message->expires_at_ms);
	offset += 8U;
	pqcp_edge_internal_write_u64(
		numeric + offset, message->not_before_ms);
	offset += 8U;
	pqcp_edge_internal_write_u32(
		numeric + offset, message->maximum_attempts);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, message->priority);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset, message->guarantee);
	offset += 4U;
	pqcp_edge_internal_write_u32(
		numeric + offset,
		(uint32_t)message->payload_length);
	offset += 4U;
	parts[0] = numeric;
	lengths[0] = offset;
	parts[1] = message->message_id;
	lengths[1] = sizeof(message->message_id);
	parts[2] =
		(const uint8_t *)message->producer_id;
	lengths[2] = strlen(message->producer_id);
	parts[3] =
		(const uint8_t *)message->consumer_id;
	lengths[3] = strlen(message->consumer_id);
	parts[4] = (const uint8_t *)message->topic;
	lengths[4] = strlen(message->topic);
	parts[5] = message->payload_digest;
	lengths[5] = sizeof(message->payload_digest);
	parts[6] = message->previous_digest;
	lengths[6] = sizeof(message->previous_digest);
	return pqcp_edge_internal_sha256_parts(
		parts, lengths, 7U, output);
}

static int authenticate_message(
	const struct pqcp_edge_message *message,
	const uint8_t key[PQCP_EDGE_KEY_BYTES],
	uint8_t tag[PQCP_EDGE_TAG_BYTES])
{
	return pqcp_edge_internal_hmac(
		key, message->message_digest,
		sizeof(message->message_digest), tag);
}

static bool consumer_matches(
	const struct pqcp_edge_message *message,
	const char *consumer_id)
{
	return consumer_id == NULL ||
	       consumer_id[0] == '\0' ||
	       strcmp(message->consumer_id,
		      consumer_id) == 0;
}

static bool topic_matches(
	const struct pqcp_edge_message *message,
	const char *topic)
{
	return topic == NULL || topic[0] == '\0' ||
	       strcmp(message->topic, topic) == 0;
}

static bool message_ready(
	const struct pqcp_edge_message *message,
	const char *consumer_id,
	const char *topic,
	uint64_t now_ms)
{
	if (!message->occupied ||
	    (message->state != PQCP_EDGE_MESSAGE_QUEUED &&
	     message->state !=
		     PQCP_EDGE_MESSAGE_RETRY_WAIT) ||
	    !consumer_matches(message, consumer_id) ||
	    !topic_matches(message, topic) ||
	    message->not_before_ms > now_ms ||
	    message->expires_at_ms <= now_ms) {
		return false;
	}
	return true;
}

static bool better_message(
	const struct pqcp_edge_message *candidate,
	const struct pqcp_edge_message *selected)
{
	if (selected == NULL) {
		return true;
	}
	if (candidate->priority != selected->priority) {
		return candidate->priority >
		       selected->priority;
	}
	if (candidate->not_before_ms !=
	    selected->not_before_ms) {
		return candidate->not_before_ms <
		       selected->not_before_ms;
	}
	if (candidate->sequence != selected->sequence) {
		return candidate->sequence <
		       selected->sequence;
	}
	return memcmp(
		       candidate->message_id,
		       selected->message_id,
		       PQCP_EDGE_MESSAGE_ID_BYTES) < 0;
}

int pqcp_edge_message_queue_init(
	struct pqcp_edge_message_queue *queue,
	struct pqcp_edge_message *messages,
	size_t capacity)
{
	if (queue == NULL || messages == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(queue, 0, sizeof(*queue));
	memset(messages, 0,
	       capacity * sizeof(*messages));
	queue->schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	queue->messages = messages;
	queue->capacity = capacity;
	k_mutex_init(&queue->lock);
	queue->initialized = true;
	return 0;
}

int pqcp_edge_message_submit(
	struct pqcp_edge_message_queue *queue,
	const struct pqcp_edge_message *message,
	const uint8_t authentication_key[PQCP_EDGE_KEY_BYTES],
	uint64_t now_ms,
	bool *replayed)
{
	struct pqcp_edge_message candidate;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int index;
	int ret = 0;

	if (queue == NULL || !queue->initialized ||
	    !message_shape_valid(message) ||
	    authentication_key == NULL || replayed == NULL ||
	    message->expires_at_ms <= now_ms ||
	    message->created_at_ms > now_ms ||
	    message->not_before_ms >
		    message->expires_at_ms) {
		return -EINVAL;
	}
	*replayed = false;
	candidate = *message;
	candidate.schema_version =
		PQCP_EDGE_SCHEMA_VERSION;
	candidate.state = PQCP_EDGE_MESSAGE_QUEUED;
	candidate.attempt_count = 0U;
	candidate.occupied = true;
	ret = payload_digest(
		&candidate, candidate.payload_digest);
	if (ret != 0) {
		return ret;
	}
	k_mutex_lock(&queue->lock, K_FOREVER);
	memcpy(candidate.previous_digest,
	       queue->chain_head,
	       sizeof(candidate.previous_digest));
	ret = message_digest(
		&candidate, candidate.message_digest);
	if (ret == 0) {
		ret = authenticate_message(
			&candidate, authentication_key,
			candidate.authentication_tag);
	}
	if (ret != 0) {
		goto out;
	}
	index = message_index(
		queue, candidate.message_id);
	if (index >= 0) {
		ret = message_digest(
			&queue->messages[index], digest);
		if (ret == 0 &&
		    pqcp_edge_internal_equal(
			    digest,
			    queue->messages[index].
				    message_digest,
			    sizeof(digest)) &&
		    pqcp_edge_internal_equal(
			    candidate.payload_digest,
			    queue->messages[index].
				    payload_digest,
			    sizeof(digest)) &&
		    candidate.sequence ==
			    queue->messages[index].sequence &&
		    candidate.producer_epoch ==
			    queue->messages[index].
				    producer_epoch &&
		    /* Routing is part of the replay identity. */
		    strncmp(candidate.producer_id,
			    queue->messages[index].producer_id,
			    sizeof(candidate.producer_id)) == 0 &&
		    strncmp(candidate.consumer_id,
			    queue->messages[index].consumer_id,
			    sizeof(candidate.consumer_id)) == 0 &&
		    strncmp(candidate.topic,
			    queue->messages[index].topic,
			    sizeof(candidate.topic)) == 0) {
			*replayed = true;
			ret = 0;
		} else if (ret == 0) {
			ret = -EKEYREJECTED;
		}
		goto out;
	}
	if (index != -ENOENT) {
		ret = index;
		goto out;
	}
	index = free_message_index(queue);
	if (index < 0) {
		ret = index;
		goto out;
	}
	queue->messages[index] = candidate;
	memcpy(queue->chain_head,
	       candidate.message_digest,
	       sizeof(queue->chain_head));
	++queue->accepted_count;
out:
	k_mutex_unlock(&queue->lock);
	return ret;
}

int pqcp_edge_message_next(
	struct pqcp_edge_message_queue *queue,
	const char *consumer_id,
	const char *topic,
	uint64_t now_ms,
	struct pqcp_edge_message **message)
{
	struct pqcp_edge_message *selected = NULL;

	if (queue == NULL || !queue->initialized ||
	    message == NULL ||
	    (consumer_id != NULL && consumer_id[0] != '\0' &&
	     !pqcp_edge_internal_text_valid(
		     consumer_id, PQCP_EDGE_ID_MAX_CHARS)) ||
	    (topic != NULL && topic[0] != '\0' &&
	     !pqcp_edge_internal_text_valid(
		     topic, PQCP_EDGE_TOPIC_MAX_CHARS))) {
		return -EINVAL;
	}
	k_mutex_lock(&queue->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < queue->capacity; ++index) {
		struct pqcp_edge_message *candidate =
			&queue->messages[index];

		if (message_ready(
			    candidate, consumer_id, topic, now_ms) &&
		    better_message(candidate, selected)) {
			selected = candidate;
		}
	}
	if (selected == NULL) {
		*message = NULL;
		k_mutex_unlock(&queue->lock);
		return -EAGAIN;
	}
	selected->state = PQCP_EDGE_MESSAGE_IN_FLIGHT;
	selected->attempt_count =
		pqcp_edge_internal_saturating_add_u32(
			selected->attempt_count, 1U);
	*message = selected;
	k_mutex_unlock(&queue->lock);
	return 0;
}

int pqcp_edge_message_acknowledge(
	struct pqcp_edge_message_queue *queue,
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES],
	uint64_t now_ms)
{
	struct pqcp_edge_message *message;
	int index;
	int ret = 0;

	if (queue == NULL || !queue->initialized ||
	    message_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&queue->lock, K_FOREVER);
	index = message_index(queue, message_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	message = &queue->messages[index];
	if (message->state ==
	    PQCP_EDGE_MESSAGE_ACKNOWLEDGED) {
		ret = -EALREADY;
	} else if (terminal_state(message->state)) {
		ret = -ESTALE;
	} else if (message->expires_at_ms <= now_ms) {
		message->state = PQCP_EDGE_MESSAGE_EXPIRED;
		++queue->expired_count;
		ret = -ETIMEDOUT;
	} else {
		message->state =
			PQCP_EDGE_MESSAGE_ACKNOWLEDGED;
		++queue->acknowledged_count;
	}
out:
	k_mutex_unlock(&queue->lock);
	return ret;
}

int pqcp_edge_message_retry(
	struct pqcp_edge_message_queue *queue,
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES],
	uint64_t retry_at_ms,
	int result)
{
	struct pqcp_edge_message *message;
	int index;
	int ret = 0;

	if (queue == NULL || !queue->initialized ||
	    message_id == NULL || result == 0) {
		return -EINVAL;
	}
	k_mutex_lock(&queue->lock, K_FOREVER);
	index = message_index(queue, message_id);
	if (index < 0) {
		ret = index;
		goto out;
	}
	message = &queue->messages[index];
	if (terminal_state(message->state)) {
		ret = -ESTALE;
	} else if (message->attempt_count >=
		   message->maximum_attempts) {
		message->state =
			PQCP_EDGE_MESSAGE_DEAD_LETTER;
		++queue->dead_letter_count;
		ret = -EOVERFLOW;
	} else if (retry_at_ms >=
		   message->expires_at_ms) {
		message->state = PQCP_EDGE_MESSAGE_EXPIRED;
		++queue->expired_count;
		ret = -ETIMEDOUT;
	} else {
		message->not_before_ms = retry_at_ms;
		message->state =
			PQCP_EDGE_MESSAGE_RETRY_WAIT;
		++queue->retried_count;
	}
out:
	k_mutex_unlock(&queue->lock);
	return ret;
}

int pqcp_edge_message_cancel(
	struct pqcp_edge_message_queue *queue,
	const uint8_t message_id[PQCP_EDGE_MESSAGE_ID_BYTES])
{
	int index;
	int ret = 0;

	if (queue == NULL || !queue->initialized ||
	    message_id == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&queue->lock, K_FOREVER);
	index = message_index(queue, message_id);
	if (index < 0) {
		ret = index;
	} else if (terminal_state(
		   queue->messages[index].state)) {
		ret = -EALREADY;
	} else {
		queue->messages[index].state =
			PQCP_EDGE_MESSAGE_CANCELLED;
	}
	k_mutex_unlock(&queue->lock);
	return ret;
}

int pqcp_edge_message_tick(
	struct pqcp_edge_message_queue *queue,
	uint64_t now_ms,
	uint32_t *changed_count)
{
	uint32_t changed = 0U;

	if (queue == NULL || !queue->initialized ||
	    changed_count == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&queue->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < queue->capacity; ++index) {
		struct pqcp_edge_message *message =
			&queue->messages[index];

		if (!message->occupied ||
		    terminal_state(message->state)) {
			continue;
		}
		if (message->expires_at_ms <= now_ms) {
			message->state =
				PQCP_EDGE_MESSAGE_EXPIRED;
			++queue->expired_count;
			++changed;
		} else if (message->state ==
			   PQCP_EDGE_MESSAGE_IN_FLIGHT &&
			   message->attempt_count >=
				   message->maximum_attempts) {
			message->state =
				PQCP_EDGE_MESSAGE_DEAD_LETTER;
			++queue->dead_letter_count;
			++changed;
		} else if (message->state ==
			   PQCP_EDGE_MESSAGE_RETRY_WAIT &&
			   message->not_before_ms <= now_ms) {
			message->state =
				PQCP_EDGE_MESSAGE_QUEUED;
			++changed;
		}
	}
	k_mutex_unlock(&queue->lock);
	*changed_count = changed;
	return 0;
}

int pqcp_edge_message_queue_audit(
	struct pqcp_edge_message_queue *queue,
	const uint8_t authentication_key[PQCP_EDGE_KEY_BYTES])
{
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	uint8_t payload[PQCP_EDGE_DIGEST_BYTES];
	uint8_t tag[PQCP_EDGE_TAG_BYTES];
	int ret = 0;

	if (queue == NULL || !queue->initialized ||
	    queue->schema_version !=
		    PQCP_EDGE_SCHEMA_VERSION ||
	    queue->messages == NULL || queue->capacity == 0U ||
	    authentication_key == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&queue->lock, K_FOREVER);
	for (size_t index = 0U;
	     index < queue->capacity && ret == 0;
	     ++index) {
		const struct pqcp_edge_message *message =
			&queue->messages[index];

		if (!message->occupied) {
			continue;
		}
		if (!message_shape_valid(message) ||
		    payload_digest(message, payload) != 0 ||
		    !pqcp_edge_internal_equal(
			    payload, message->payload_digest,
			    sizeof(payload)) ||
		    message_digest(message, digest) != 0 ||
		    !pqcp_edge_internal_equal(
			    digest, message->message_digest,
			    sizeof(digest)) ||
		    authenticate_message(
			    message, authentication_key,
			    tag) != 0 ||
		    !pqcp_edge_internal_equal(
			    tag, message->authentication_tag,
			    sizeof(tag))) {
			ret = -EBADMSG;
			break;
		}
		for (size_t other = index + 1U;
		     other < queue->capacity; ++other) {
			if (queue->messages[other].occupied &&
			    pqcp_edge_internal_equal(
				    message->message_id,
				    queue->messages[other].
					    message_id,
				    sizeof(message->message_id))) {
				ret = -EEXIST;
				break;
			}
		}
	}
	k_mutex_unlock(&queue->lock);
	return ret;
}
