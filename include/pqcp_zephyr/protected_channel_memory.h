/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deterministic bounded in-memory protected-channel transport.
 *
 * Stability: test/replay support.
 */

#ifndef PQCP_ZEPHYR_PROTECTED_CHANNEL_MEMORY_H_
#define PQCP_ZEPHYR_PROTECTED_CHANNEL_MEMORY_H_

#include <pqcp_zephyr/protected_channel.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pqcp_channel_memory_pipe {
	uint8_t *buffer;
	size_t capacity;
	size_t read_offset;
	size_t write_offset;
	size_t used;
	bool closed;
	struct k_mutex lock;
	struct k_sem data_ready;
	struct k_sem space_ready;
};

struct pqcp_channel_memory_endpoint {
	struct pqcp_channel_memory_pipe *incoming;
	struct pqcp_channel_memory_pipe *outgoing;
	uint8_t exporter[PQCP_CHANNEL_EXPORTER_BYTES];
	bool initialized;
	bool closed;
};

int pqcp_channel_memory_pipe_init(
	struct pqcp_channel_memory_pipe *pipe,
	uint8_t *buffer,
	size_t capacity);
int pqcp_channel_memory_pair_init(
	struct pqcp_channel_memory_endpoint *client,
	struct pqcp_channel_memory_endpoint *server,
	struct pqcp_channel_memory_pipe *client_to_server,
	struct pqcp_channel_memory_pipe *server_to_client,
	const uint8_t exporter[PQCP_CHANNEL_EXPORTER_BYTES]);
int pqcp_channel_memory_make_transport(
	struct pqcp_channel_memory_endpoint *endpoint,
	struct pqcp_channel_transport *transport);
int pqcp_channel_memory_tamper_next(
	struct pqcp_channel_memory_pipe *pipe,
	size_t offset,
	uint8_t mask);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_PROTECTED_CHANNEL_MEMORY_H_ */
