/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Replay-safe, idempotent, fixed-capacity fleet command queue.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <pqcp_zephyr/fleet_operations.h>
#include <pqcp_zephyr/errno.h>

#include "runtime_internal.h"

static bool all_zero(const uint8_t *value, size_t length);

static uint32_t valid_flags(void)
{
	return PQCP_FLEET_COMMAND_HIGH_PRIORITY |
	       PQCP_FLEET_COMMAND_IDEMPOTENT |
	       PQCP_FLEET_COMMAND_REQUIRE_ONLINE |
	       PQCP_FLEET_COMMAND_REQUIRE_CHANNEL_IDENTITY |
	       PQCP_FLEET_COMMAND_ALLOW_RECOVERY;
}

static bool operation_valid(
	enum pqcp_fleet_operation_type operation)
{
	return operation > PQCP_FLEET_OPERATION_NONE &&
	       operation < PQCP_FLEET_OPERATION_COUNT;
}

static bool terminal_state(
	enum pqcp_fleet_command_state state)
{
	return state == PQCP_FLEET_COMMAND_STATE_COMPLETED ||
	       state == PQCP_FLEET_COMMAND_STATE_REJECTED ||
	       state == PQCP_FLEET_COMMAND_STATE_CANCELLED ||
	       state == PQCP_FLEET_COMMAND_STATE_EXPIRED;
}

static int command_validate(
	const struct pqcp_fleet_command *command)
{
	if (command == NULL ||
	    command->schema_version !=
		    PQCP_FLEET_OPERATIONS_SCHEMA_VERSION ||
	    command->command_id == 0U ||
	    command->sequence == 0U ||
	    command->submitted_at_ms == 0U ||
	    command->deadline_ms <=
		    command->submitted_at_ms ||
	    !operation_valid(command->operation) ||
	    (command->flags & ~valid_flags()) != 0U ||
	    command->maximum_attempts == 0U ||
	    command->attempts > command->maximum_attempts ||
	    all_zero(
		    command->payload_digest,
		    sizeof(command->payload_digest))) {
		return -EINVAL;
	}
	if ((command->flags &
	     PQCP_FLEET_COMMAND_IDEMPOTENT) != 0U &&
	    all_zero(
		    command->idempotency_key,
		    sizeof(command->idempotency_key))) {
		return -EINVAL;
	}
	return 0;
}

/*
 * The command engine intentionally uses a local constant-time helper instead
 * of depending on the optional crypto broker.
 */
static bool secure_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static bool all_zero(const uint8_t *value, size_t length)
{
	uint8_t aggregate = 0U;

	for (size_t index = 0U; index < length; ++index) {
		aggregate |= value[index];
	}
	return aggregate == 0U;
}

static uint32_t next_generation(
	struct pqcp_fleet_command_queue *queue)
{
	queue->next_generation++;
	if (queue->next_generation == 0U) {
		queue->next_generation++;
	}
	return queue->next_generation;
}

static int free_index(
	const struct pqcp_fleet_command_queue *queue)
{
	int oldest_terminal = -1;
	uint64_t oldest_sequence = UINT64_MAX;

	for (size_t index = 0U; index < queue->capacity;
	     ++index) {
		const struct pqcp_fleet_command *command =
			&queue->commands[index];

		if (command->state == PQCP_FLEET_COMMAND_STATE_EMPTY) {
			return (int)index;
		}
		if (terminal_state(command->state) &&
		    command->sequence < oldest_sequence) {
			oldest_sequence = command->sequence;
			oldest_terminal = (int)index;
		}
	}
	return oldest_terminal;
}

static int command_id_index(
	const struct pqcp_fleet_command_queue *queue,
	uint64_t command_id)
{
	for (size_t index = 0U; index < queue->capacity;
	     ++index) {
		if (queue->commands[index].state !=
			    PQCP_FLEET_COMMAND_STATE_EMPTY &&
		    queue->commands[index].command_id == command_id) {
			return (int)index;
		}
	}
	return -1;
}

static int idempotency_index(
	const struct pqcp_fleet_command_queue *queue,
	const uint8_t key[PQCP_FLEET_DIGEST_BYTES])
{
	for (size_t index = 0U; index < queue->capacity;
	     ++index) {
		const struct pqcp_fleet_command *command =
			&queue->commands[index];

		if (command->state != PQCP_FLEET_COMMAND_STATE_EMPTY &&
		    (command->flags &
		     PQCP_FLEET_COMMAND_IDEMPOTENT) != 0U &&
		    secure_equal(
			    command->idempotency_key, key,
			    PQCP_FLEET_DIGEST_BYTES)) {
			return (int)index;
		}
	}
	return -1;
}

int pqcp_fleet_command_queue_init(
	struct pqcp_fleet_command_queue *queue,
	struct pqcp_fleet_command *commands,
	size_t capacity)
{
	if (queue == NULL || commands == NULL ||
	    capacity == 0U) {
		return -EINVAL;
	}
	memset(queue, 0, sizeof(*queue));
	memset(commands, 0, sizeof(*commands) * capacity);
	queue->schema_version =
		PQCP_FLEET_OPERATIONS_SCHEMA_VERSION;
	queue->commands = commands;
	queue->capacity = capacity;
	k_mutex_init(&queue->lock);
	queue->initialized = true;
	return 0;
}

int pqcp_fleet_command_submit(
	struct pqcp_fleet_command_queue *queue,
	const struct pqcp_fleet_command *command,
	struct pqcp_fleet_command **accepted,
	bool *replayed)
{
	struct pqcp_fleet_command *destination;
	int index;
	int ret;

	if (queue == NULL || !queue->initialized ||
	    command_validate(command) != 0 ||
	    accepted == NULL || replayed == NULL ||
	    command->state != PQCP_FLEET_COMMAND_STATE_QUEUED) {
		return -EINVAL;
	}
	*accepted = NULL;
	*replayed = false;
	ret = k_mutex_lock(&queue->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = command_id_index(queue, command->command_id);
	if (index >= 0) {
		destination = &queue->commands[index];
		if (destination->sequence == command->sequence &&
		    destination->operation == command->operation &&
		    secure_equal(
			    destination->payload_digest,
			    command->payload_digest,
			    PQCP_FLEET_DIGEST_BYTES)) {
			*accepted = destination;
			*replayed = true;
			queue->replayed_count++;
			(void)k_mutex_unlock(&queue->lock);
			return 0;
		}
		queue->rejected_count++;
		(void)k_mutex_unlock(&queue->lock);
		return -EKEYREJECTED;
	}
	if ((command->flags &
	     PQCP_FLEET_COMMAND_IDEMPOTENT) != 0U) {
		index = idempotency_index(
			queue, command->idempotency_key);
		if (index >= 0) {
			destination = &queue->commands[index];
			if (destination->operation ==
				    command->operation &&
			    secure_equal(
				    destination->payload_digest,
				    command->payload_digest,
				    PQCP_FLEET_DIGEST_BYTES)) {
				*accepted = destination;
				*replayed = true;
				queue->replayed_count++;
				(void)k_mutex_unlock(&queue->lock);
				return 0;
			}
			queue->rejected_count++;
			(void)k_mutex_unlock(&queue->lock);
			return -EKEYREJECTED;
		}
	}
	if (command->sequence <= queue->last_sequence) {
		queue->rejected_count++;
		(void)k_mutex_unlock(&queue->lock);
		return -ESTALE;
	}
	index = free_index(queue);
	if (index < 0) {
		queue->rejected_count++;
		(void)k_mutex_unlock(&queue->lock);
		return -ENOSPC;
	}
	destination = &queue->commands[index];
	pqcp_runtime_secure_zero(
		destination, sizeof(*destination));
	*destination = *command;
	destination->generation = next_generation(queue);
	destination->attempts = 0U;
	destination->retry_after_ms = 0U;
	destination->result = 0;
	memset(destination->result_digest, 0,
	       sizeof(destination->result_digest));
	queue->last_sequence = command->sequence;
	queue->accepted_count++;
	*accepted = destination;
	(void)k_mutex_unlock(&queue->lock);
	return 0;
}

static bool runnable(
	const struct pqcp_fleet_command *command,
	uint64_t now_ms)
{
	if (command->deadline_ms <= now_ms) {
		return false;
	}
	if (command->state == PQCP_FLEET_COMMAND_STATE_QUEUED) {
		return true;
	}
	return command->state ==
		       PQCP_FLEET_COMMAND_STATE_RETRY_WAIT &&
	       command->retry_after_ms <= now_ms;
}

static bool precedes(
	const struct pqcp_fleet_command *candidate,
	const struct pqcp_fleet_command *selected)
{
	const bool candidate_high =
		(candidate->flags &
		 PQCP_FLEET_COMMAND_HIGH_PRIORITY) != 0U;
	const bool selected_high =
		(selected->flags &
		 PQCP_FLEET_COMMAND_HIGH_PRIORITY) != 0U;

	if (candidate_high != selected_high) {
		return candidate_high;
	}
	if (candidate->deadline_ms != selected->deadline_ms) {
		return candidate->deadline_ms <
		       selected->deadline_ms;
	}
	return candidate->sequence < selected->sequence;
}

int pqcp_fleet_command_next(
	struct pqcp_fleet_command_queue *queue,
	uint64_t now_ms,
	struct pqcp_fleet_command **command)
{
	struct pqcp_fleet_command *selected = NULL;
	int ret;

	if (queue == NULL || !queue->initialized ||
	    now_ms == 0U || command == NULL) {
		return -EINVAL;
	}
	*command = NULL;
	ret = k_mutex_lock(&queue->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < queue->capacity;
	     ++index) {
		struct pqcp_fleet_command *candidate =
			&queue->commands[index];

		if ((candidate->state ==
			     PQCP_FLEET_COMMAND_STATE_QUEUED ||
		     candidate->state ==
			     PQCP_FLEET_COMMAND_STATE_RETRY_WAIT) &&
		    candidate->deadline_ms <= now_ms) {
			candidate->state =
				PQCP_FLEET_COMMAND_STATE_EXPIRED;
			candidate->result = -ETIMEDOUT;
			queue->rejected_count++;
			continue;
		}
		if (runnable(candidate, now_ms) &&
		    (selected == NULL ||
		     precedes(candidate, selected))) {
			selected = candidate;
		}
	}
	if (selected == NULL) {
		(void)k_mutex_unlock(&queue->lock);
		return -ENOENT;
	}
	selected->state = PQCP_FLEET_COMMAND_STATE_RUNNING;
	selected->attempts++;
	*command = selected;
	(void)k_mutex_unlock(&queue->lock);
	return 0;
}

int pqcp_fleet_command_complete(
	struct pqcp_fleet_command_queue *queue,
	uint64_t command_id,
	int result,
	const uint8_t *result_data,
	size_t result_length,
	uint64_t now_ms)
{
	struct pqcp_fleet_command *command;
	int index;
	int ret;

	if (queue == NULL || !queue->initialized ||
	    command_id == 0U ||
	    (result_data == NULL && result_length != 0U) ||
	    now_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&queue->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = command_id_index(queue, command_id);
	if (index < 0) {
		(void)k_mutex_unlock(&queue->lock);
		return -ENOENT;
	}
	command = &queue->commands[index];
	if (command->state != PQCP_FLEET_COMMAND_STATE_RUNNING) {
		(void)k_mutex_unlock(&queue->lock);
		return -EALREADY;
	}
	if (now_ms > command->deadline_ms) {
		command->state = PQCP_FLEET_COMMAND_STATE_EXPIRED;
		command->result = -ETIMEDOUT;
		queue->rejected_count++;
		(void)k_mutex_unlock(&queue->lock);
		return -ETIMEDOUT;
	}
	ret = pqcp_runtime_internal_sha256(
		result_data, result_length,
		command->result_digest);
	if (ret == 0) {
		command->result = result;
		command->state = result == 0 ?
			PQCP_FLEET_COMMAND_STATE_COMPLETED :
			PQCP_FLEET_COMMAND_STATE_REJECTED;
		queue->completed_count++;
	}
	(void)k_mutex_unlock(&queue->lock);
	return ret;
}

int pqcp_fleet_command_retry(
	struct pqcp_fleet_command_queue *queue,
	uint64_t command_id,
	uint64_t retry_after_ms,
	int result)
{
	struct pqcp_fleet_command *command;
	int index;
	int ret;

	if (queue == NULL || !queue->initialized ||
	    command_id == 0U || retry_after_ms == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&queue->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = command_id_index(queue, command_id);
	if (index < 0) {
		(void)k_mutex_unlock(&queue->lock);
		return -ENOENT;
	}
	command = &queue->commands[index];
	if (command->state != PQCP_FLEET_COMMAND_STATE_RUNNING) {
		(void)k_mutex_unlock(&queue->lock);
		return -EALREADY;
	}
	if (command->attempts >= command->maximum_attempts ||
	    retry_after_ms >= command->deadline_ms) {
		command->state = PQCP_FLEET_COMMAND_STATE_REJECTED;
		command->result = result != 0 ? result : -EAGAIN;
		queue->rejected_count++;
		(void)k_mutex_unlock(&queue->lock);
		return -EDQUOT;
	}
	command->state = PQCP_FLEET_COMMAND_STATE_RETRY_WAIT;
	command->retry_after_ms = retry_after_ms;
	command->result = result;
	(void)k_mutex_unlock(&queue->lock);
	return 0;
}

int pqcp_fleet_command_cancel(
	struct pqcp_fleet_command_queue *queue,
	uint64_t command_id)
{
	struct pqcp_fleet_command *command;
	int index;
	int ret;

	if (queue == NULL || !queue->initialized ||
	    command_id == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&queue->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	index = command_id_index(queue, command_id);
	if (index < 0) {
		(void)k_mutex_unlock(&queue->lock);
		return -ENOENT;
	}
	command = &queue->commands[index];
	if (terminal_state(command->state)) {
		(void)k_mutex_unlock(&queue->lock);
		return -EALREADY;
	}
	command->state = PQCP_FLEET_COMMAND_STATE_CANCELLED;
	command->result = -ECANCELED;
	queue->cancelled_count++;
	(void)k_mutex_unlock(&queue->lock);
	return 0;
}

int pqcp_fleet_command_expire(
	struct pqcp_fleet_command_queue *queue,
	uint64_t now_ms,
	uint32_t *expired_count)
{
	uint32_t expired = 0U;
	int ret;

	if (queue == NULL || !queue->initialized ||
	    now_ms == 0U || expired_count == NULL) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&queue->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < queue->capacity;
	     ++index) {
		struct pqcp_fleet_command *command =
			&queue->commands[index];

		if (!terminal_state(command->state) &&
		    command->state != PQCP_FLEET_COMMAND_STATE_EMPTY &&
		    command->deadline_ms <= now_ms) {
			command->state =
				PQCP_FLEET_COMMAND_STATE_EXPIRED;
			command->result = -ETIMEDOUT;
			expired++;
			queue->rejected_count++;
		}
	}
	(void)k_mutex_unlock(&queue->lock);
	*expired_count = expired;
	return 0;
}

int pqcp_fleet_command_queue_audit(
	struct pqcp_fleet_command_queue *queue)
{
	int ret;

	if (queue == NULL || !queue->initialized ||
	    queue->schema_version !=
		    PQCP_FLEET_OPERATIONS_SCHEMA_VERSION ||
	    queue->commands == NULL || queue->capacity == 0U) {
		return -EINVAL;
	}
	ret = k_mutex_lock(&queue->lock, K_FOREVER);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U; index < queue->capacity;
	     ++index) {
		const struct pqcp_fleet_command *command =
			&queue->commands[index];

		if (command->state == PQCP_FLEET_COMMAND_STATE_EMPTY) {
			continue;
		}
		if (command_validate(command) != 0 ||
		    command->generation == 0U ||
		    command->state >
			    PQCP_FLEET_COMMAND_STATE_EXPIRED) {
			(void)k_mutex_unlock(&queue->lock);
			return -EBADMSG;
		}
		for (size_t other = index + 1U;
		     other < queue->capacity; ++other) {
			const struct pqcp_fleet_command *candidate =
				&queue->commands[other];

			if (candidate->state ==
			    PQCP_FLEET_COMMAND_STATE_EMPTY) {
				continue;
			}
			if (candidate->command_id ==
			    command->command_id) {
				(void)k_mutex_unlock(
					&queue->lock);
				return -EEXIST;
			}
			if ((candidate->flags &
			     PQCP_FLEET_COMMAND_IDEMPOTENT) != 0U &&
			    (command->flags &
			     PQCP_FLEET_COMMAND_IDEMPOTENT) != 0U &&
			    secure_equal(
				    candidate->idempotency_key,
				    command->idempotency_key,
				    PQCP_FLEET_DIGEST_BYTES)) {
				(void)k_mutex_unlock(
					&queue->lock);
				return -EEXIST;
			}
		}
	}
	(void)k_mutex_unlock(&queue->lock);
	return 0;
}
