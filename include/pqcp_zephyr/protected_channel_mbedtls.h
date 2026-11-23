/*
 * SPDX-License-Identifier: MIT
 *
 * Direct mbedTLS transport adapter for the PQCP protected channel.
 * The socket descriptor is optional; pass -1 for an application-supplied BIO.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_PROTECTED_CHANNEL_MBEDTLS_H_
#define PQCP_ZEPHYR_PROTECTED_CHANNEL_MBEDTLS_H_

#include <mbedtls/ssl.h>

#include <pqcp_zephyr/protected_channel.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pqcp_channel_mbedtls_context {
	mbedtls_ssl_context *ssl;
	int socket_fd;
	uint32_t default_timeout_ms;
	bool owns_socket;
	bool handshake_complete;
};

int pqcp_channel_mbedtls_transport_init(
	struct pqcp_channel_transport *transport,
	struct pqcp_channel_mbedtls_context *context,
	mbedtls_ssl_context *ssl,
	int socket_fd,
	uint32_t default_timeout_ms,
	bool owns_socket);

int pqcp_channel_mbedtls_send(
	void *context,
	const uint8_t *buffer,
	size_t length,
	uint32_t timeout_ms);
int pqcp_channel_mbedtls_receive(
	void *context,
	uint8_t *buffer,
	size_t capacity,
	size_t *received,
	uint32_t timeout_ms);
int pqcp_channel_mbedtls_export(
	void *context,
	const char *label,
	const uint8_t *export_context,
	size_t export_context_length,
	uint8_t *output,
	size_t output_length);
int pqcp_channel_mbedtls_close(void *context);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_PROTECTED_CHANNEL_MBEDTLS_H_ */
