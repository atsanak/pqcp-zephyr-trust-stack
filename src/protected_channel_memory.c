/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deterministic bounded in-memory transport for protocol replay.
 */

#include <errno.h>
#include <string.h>

#include <pqcp_zephyr/protected_channel_memory.h>

#include "runtime_internal.h"

static size_t contiguous_write_capacity(
	const struct pqcp_channel_memory_pipe *pipe)
{
	if (pipe->write_offset >= pipe->read_offset) {
		return pipe->capacity - pipe->write_offset;
	}
	return pipe->read_offset - pipe->write_offset;
}

static size_t contiguous_read_capacity(
	const struct pqcp_channel_memory_pipe *pipe)
{
	if (pipe->used == 0U) {
		return 0U;
	}
	if (pipe->read_offset < pipe->write_offset) {
		return pipe->write_offset - pipe->read_offset;
	}
	return pipe->capacity - pipe->read_offset;
}

int pqcp_channel_memory_pipe_init(
	struct pqcp_channel_memory_pipe *pipe,
	uint8_t *buffer,
	size_t capacity)
{
	if (pipe == NULL || buffer == NULL || capacity < 64U) {
		return -EINVAL;
	}
	memset(pipe, 0, sizeof(*pipe));
	memset(buffer, 0, capacity);
	pipe->buffer = buffer;
	pipe->capacity = capacity;
	k_mutex_init(&pipe->lock);
	k_sem_init(&pipe->data_ready, 0U, 1U);
	k_sem_init(&pipe->space_ready, 0U, 1U);
	return 0;
}

static int memory_send(
	void *context,
	const uint8_t *buffer,
	size_t length,
	uint32_t timeout_ms)
{
	struct pqcp_channel_memory_endpoint *endpoint = context;
	struct pqcp_channel_memory_pipe *pipe;
	size_t offset = 0U;
	int64_t deadline;

	if (endpoint == NULL || !endpoint->initialized ||
	    endpoint->closed ||
	    (buffer == NULL && length != 0U)) {
		return -EINVAL;
	}
	pipe = endpoint->outgoing;
	deadline = k_uptime_get() + timeout_ms;
	while (offset < length) {
		size_t writable;
		size_t chunk;

		if (k_mutex_lock(&pipe->lock, K_FOREVER) != 0) {
			return -EIO;
		}
		if (pipe->closed) {
			(void)k_mutex_unlock(&pipe->lock);
			return -EPIPE;
		}
		writable = pipe->capacity - pipe->used;
		if (writable == 0U) {
			(void)k_mutex_unlock(&pipe->lock);
			if (k_uptime_get() >= deadline) {
				return -ETIMEDOUT;
			}
			(void)k_sem_take(
				&pipe->space_ready, K_MSEC(1));
			continue;
		}
		chunk = contiguous_write_capacity(pipe);
		if (chunk > writable) {
			chunk = writable;
		}
		if (chunk > length - offset) {
			chunk = length - offset;
		}
		memcpy(pipe->buffer + pipe->write_offset,
		       buffer + offset, chunk);
		pipe->write_offset =
			(pipe->write_offset + chunk) % pipe->capacity;
		pipe->used += chunk;
		offset += chunk;
		k_sem_give(&pipe->data_ready);
		(void)k_mutex_unlock(&pipe->lock);
	}
	return 0;
}

static int memory_receive(
	void *context,
	uint8_t *buffer,
	size_t capacity,
	size_t *received,
	uint32_t timeout_ms)
{
	struct pqcp_channel_memory_endpoint *endpoint = context;
	struct pqcp_channel_memory_pipe *pipe;
	int64_t deadline;

	if (endpoint == NULL || !endpoint->initialized ||
	    buffer == NULL || capacity == 0U || received == NULL) {
		return -EINVAL;
	}
	pipe = endpoint->incoming;
	deadline = k_uptime_get() + timeout_ms;
	for (;;) {
		size_t readable;
		size_t chunk;

		if (k_mutex_lock(&pipe->lock, K_FOREVER) != 0) {
			return -EIO;
		}
		if (pipe->used == 0U) {
			const bool closed = pipe->closed;

			(void)k_mutex_unlock(&pipe->lock);
			if (closed) {
				*received = 0U;
				return -ECONNRESET;
			}
			if (k_uptime_get() >= deadline) {
				*received = 0U;
				return -ETIMEDOUT;
			}
			(void)k_sem_take(
				&pipe->data_ready, K_MSEC(1));
			continue;
		}
		readable = pipe->used;
		chunk = contiguous_read_capacity(pipe);
		if (chunk > readable) {
			chunk = readable;
		}
		if (chunk > capacity) {
			chunk = capacity;
		}
		memcpy(buffer, pipe->buffer + pipe->read_offset,
		       chunk);
		pqcp_runtime_secure_zero(
			pipe->buffer + pipe->read_offset, chunk);
		pipe->read_offset =
			(pipe->read_offset + chunk) % pipe->capacity;
		pipe->used -= chunk;
		*received = chunk;
		k_sem_give(&pipe->space_ready);
		(void)k_mutex_unlock(&pipe->lock);
		return 0;
	}
}

static int memory_export(
	void *context,
	const char *label,
	const uint8_t *export_context,
	size_t export_context_length,
	uint8_t *output,
	size_t output_length)
{
	struct pqcp_channel_memory_endpoint *endpoint = context;
	uint8_t context_hash[PQCP_CHANNEL_HASH_BYTES];
	uint8_t input[PQCP_CHANNEL_EXPORTER_BYTES +
		      PQCP_CHANNEL_HASH_BYTES];
	int ret;

	if (endpoint == NULL || !endpoint->initialized ||
	    label == NULL ||
	    strcmp(label, PQCP_CHANNEL_EXPORTER_LABEL) != 0 ||
	    (export_context == NULL &&
	     export_context_length != 0U) ||
	    output == NULL ||
	    output_length != PQCP_CHANNEL_EXPORTER_BYTES) {
		return -EINVAL;
	}
	ret = pqcp_runtime_internal_sha256(
		export_context, export_context_length,
		context_hash);
	if (ret != 0) {
		return ret;
	}
	memcpy(input, endpoint->exporter,
	       PQCP_CHANNEL_EXPORTER_BYTES);
	memcpy(input + PQCP_CHANNEL_EXPORTER_BYTES,
	       context_hash, sizeof(context_hash));
	ret = pqcp_runtime_internal_sha256(
		input, sizeof(input), output);
	pqcp_runtime_secure_zero(input, sizeof(input));
	pqcp_runtime_secure_zero(
		context_hash, sizeof(context_hash));
	return ret;
}

static int memory_close(void *context)
{
	struct pqcp_channel_memory_endpoint *endpoint = context;

	if (endpoint == NULL || !endpoint->initialized) {
		return -EINVAL;
	}
	endpoint->closed = true;
	if (k_mutex_lock(
		    &endpoint->outgoing->lock, K_FOREVER) == 0) {
		endpoint->outgoing->closed = true;
		k_sem_give(&endpoint->outgoing->data_ready);
		k_sem_give(&endpoint->outgoing->space_ready);
		(void)k_mutex_unlock(&endpoint->outgoing->lock);
	}
	return 0;
}

int pqcp_channel_memory_pair_init(
	struct pqcp_channel_memory_endpoint *client,
	struct pqcp_channel_memory_endpoint *server,
	struct pqcp_channel_memory_pipe *client_to_server,
	struct pqcp_channel_memory_pipe *server_to_client,
	const uint8_t exporter[PQCP_CHANNEL_EXPORTER_BYTES])
{
	if (client == NULL || server == NULL ||
	    client_to_server == NULL ||
	    server_to_client == NULL || exporter == NULL ||
	    client_to_server->buffer == NULL ||
	    server_to_client->buffer == NULL) {
		return -EINVAL;
	}
	memset(client, 0, sizeof(*client));
	memset(server, 0, sizeof(*server));
	client->incoming = server_to_client;
	client->outgoing = client_to_server;
	server->incoming = client_to_server;
	server->outgoing = server_to_client;
	memcpy(client->exporter, exporter,
	       PQCP_CHANNEL_EXPORTER_BYTES);
	memcpy(server->exporter, exporter,
	       PQCP_CHANNEL_EXPORTER_BYTES);
	client->initialized = true;
	server->initialized = true;
	return 0;
}

int pqcp_channel_memory_make_transport(
	struct pqcp_channel_memory_endpoint *endpoint,
	struct pqcp_channel_transport *transport)
{
	if (endpoint == NULL || !endpoint->initialized ||
	    transport == NULL) {
		return -EINVAL;
	}
	memset(transport, 0, sizeof(*transport));
	transport->context = endpoint;
	transport->send = memory_send;
	transport->receive = memory_receive;
	transport->export_keying_material = memory_export;
	transport->close = memory_close;
	return 0;
}

int pqcp_channel_memory_tamper_next(
	struct pqcp_channel_memory_pipe *pipe,
	size_t offset,
	uint8_t mask)
{
	size_t physical;

	if (pipe == NULL || pipe->buffer == NULL ||
	    mask == 0U) {
		return -EINVAL;
	}
	if (k_mutex_lock(&pipe->lock, K_FOREVER) != 0) {
		return -EIO;
	}
	if (offset >= pipe->used) {
		(void)k_mutex_unlock(&pipe->lock);
		return -ERANGE;
	}
	physical = (pipe->read_offset + offset) % pipe->capacity;
	pipe->buffer[physical] ^= mask;
	(void)k_mutex_unlock(&pipe->lock);
	return 0;
}
