/*
 * SPDX-License-Identifier: MIT
 *
 * Direct mbedTLS PSK endpoint used by the QEMU protected-channel demo.
 *
 * Stability: experimental. Applications may instead supply their own
 * configured mbedTLS context.
 */

#ifndef PQCP_ZEPHYR_PROTECTED_CHANNEL_TLS_H_
#define PQCP_ZEPHYR_PROTECTED_CHANNEL_TLS_H_

#include <mbedtls/ssl.h>

#include <pqcp_zephyr/protected_channel_mbedtls.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_TLS_ENDPOINT_MAX_PSK_BYTES 64U
#define PQCP_TLS_ENDPOINT_MAX_IDENTITY_BYTES 64U

struct pqcp_tls_endpoint {
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config config;
	enum pqcp_channel_role role;
	int socket_fd;
	uint8_t psk[PQCP_TLS_ENDPOINT_MAX_PSK_BYTES];
	size_t psk_length;
	uint8_t identity[PQCP_TLS_ENDPOINT_MAX_IDENTITY_BYTES];
	size_t identity_length;
	bool configured;
	bool handshake_complete;
	bool owns_socket;
};

int pqcp_tls_endpoint_init_psk(
	struct pqcp_tls_endpoint *endpoint,
	enum pqcp_channel_role role,
	const uint8_t *psk,
	size_t psk_length,
	const uint8_t *identity,
	size_t identity_length);
int pqcp_tls_endpoint_handshake_bio(
	struct pqcp_tls_endpoint *endpoint,
	void *bio_context,
	mbedtls_ssl_send_t *send_callback,
	mbedtls_ssl_recv_t *receive_callback,
	mbedtls_ssl_recv_timeout_t *receive_timeout_callback,
	uint32_t timeout_ms);
int pqcp_tls_endpoint_handshake(
	struct pqcp_tls_endpoint *endpoint,
	int socket_fd,
	bool owns_socket,
	uint32_t timeout_ms);
int pqcp_tls_endpoint_make_transport(
	struct pqcp_tls_endpoint *endpoint,
	struct pqcp_channel_transport *transport,
	struct pqcp_channel_mbedtls_context *adapter,
	uint32_t timeout_ms);
void pqcp_tls_endpoint_free(
	struct pqcp_tls_endpoint *endpoint);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_PROTECTED_CHANNEL_TLS_H_ */
