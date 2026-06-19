/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Reusable direct-mbedTLS TLS 1.3 PSK endpoint.
 */

#include <errno.h>
#include <string.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>

#include <zephyr/kernel.h>

#if defined(CONFIG_PQCP_PROTECTED_CHANNEL_TCP)
#include <zephyr/net/socket.h>
#endif

#include <pqcp_zephyr/protected_channel_tls.h>

#if defined(CONFIG_PQCP_PROTECTED_CHANNEL_TCP)
static int endpoint_socket_send(
	void *context,
	const unsigned char *buffer,
	size_t length)
{
	const int socket_fd = *(int *)context;
	ssize_t sent;

	do {
		sent = zsock_send(socket_fd, buffer, length, 0);
	} while (sent < 0 && errno == EINTR);
	if (sent > 0) {
		return (int)sent;
	}
	if (sent == 0) {
		return MBEDTLS_ERR_SSL_CONN_EOF;
	}
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	if (errno == ECONNRESET || errno == EPIPE) {
		return MBEDTLS_ERR_SSL_CONN_EOF;
	}
	return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int endpoint_socket_receive(
	void *context,
	unsigned char *buffer,
	size_t length)
{
	const int socket_fd = *(int *)context;
	ssize_t received;

	do {
		received = zsock_recv(socket_fd, buffer, length, 0);
	} while (received < 0 && errno == EINTR);
	if (received > 0) {
		return (int)received;
	}
	if (received == 0) {
		return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
	}
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	if (errno == ECONNRESET) {
		return MBEDTLS_ERR_SSL_CONN_EOF;
	}
	return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int endpoint_socket_receive_timeout(
	void *context,
	unsigned char *buffer,
	size_t length,
	uint32_t timeout_ms)
{
	const int socket_fd = *(int *)context;
	struct zsock_pollfd poll_descriptor = {
		.fd = socket_fd,
		.events = ZSOCK_POLLIN,
	};
	int ret;

	ret = zsock_poll(
		&poll_descriptor, 1, (int)timeout_ms);
	if (ret == 0) {
		return MBEDTLS_ERR_SSL_TIMEOUT;
	}
	if (ret < 0) {
		return errno == EINTR ?
			MBEDTLS_ERR_SSL_WANT_READ :
			MBEDTLS_ERR_SSL_INTERNAL_ERROR;
	}
	if ((poll_descriptor.revents &
	     (ZSOCK_POLLERR | ZSOCK_POLLHUP |
	      ZSOCK_POLLNVAL)) != 0) {
		return MBEDTLS_ERR_SSL_CONN_EOF;
	}
	return endpoint_socket_receive(
		context, buffer, length);
}
#endif

static int configure_psk(
	struct pqcp_tls_endpoint *endpoint)
{
	int ret = mbedtls_ssl_conf_psk(
		&endpoint->config,
		endpoint->psk, endpoint->psk_length,
		endpoint->identity, endpoint->identity_length);

	return ret == 0 ? 0 : -EIO;
}

int pqcp_tls_endpoint_init_psk(
	struct pqcp_tls_endpoint *endpoint,
	enum pqcp_channel_role role,
	const uint8_t *psk,
	size_t psk_length,
	const uint8_t *identity,
	size_t identity_length)
{
	int endpoint_mode;
	int ret;

	if (endpoint == NULL ||
	    (role != PQCP_CHANNEL_ROLE_CLIENT &&
	     role != PQCP_CHANNEL_ROLE_SERVER) ||
	    psk == NULL || psk_length == 0U ||
	    psk_length > sizeof(endpoint->psk) ||
	    identity == NULL || identity_length == 0U ||
	    identity_length > sizeof(endpoint->identity)) {
		return -EINVAL;
	}
	memset(endpoint, 0, sizeof(*endpoint));
	endpoint->socket_fd = -1;
	endpoint->role = role;
	memcpy(endpoint->psk, psk, psk_length);
	endpoint->psk_length = psk_length;
	memcpy(endpoint->identity, identity, identity_length);
	endpoint->identity_length = identity_length;
	mbedtls_ssl_init(&endpoint->ssl);
	mbedtls_ssl_config_init(&endpoint->config);
	endpoint_mode = role == PQCP_CHANNEL_ROLE_CLIENT ?
		MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER;
	ret = mbedtls_ssl_config_defaults(
		&endpoint->config, endpoint_mode,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		pqcp_tls_endpoint_free(endpoint);
		return -EIO;
	}
	mbedtls_ssl_conf_min_tls_version(
		&endpoint->config,
		MBEDTLS_SSL_VERSION_TLS1_3);
	mbedtls_ssl_conf_max_tls_version(
		&endpoint->config,
		MBEDTLS_SSL_VERSION_TLS1_3);
	mbedtls_ssl_conf_read_timeout(
		&endpoint->config, 5000U);
	ret = configure_psk(endpoint);
	if (ret != 0) {
		pqcp_tls_endpoint_free(endpoint);
		return ret;
	}
	ret = mbedtls_ssl_setup(
		&endpoint->ssl, &endpoint->config);
	if (ret != 0) {
		pqcp_tls_endpoint_free(endpoint);
		return -EIO;
	}
	endpoint->configured = true;
	return 0;
}

#if defined(CONFIG_PQCP_PROTECTED_CHANNEL_TCP)
static int configure_socket_timeout(
	int socket_fd,
	int option,
	uint32_t timeout_ms)
{
	struct timeval timeout = {
		.tv_sec = timeout_ms / 1000U,
		.tv_usec = (timeout_ms % 1000U) * 1000U,
	};

	return zsock_setsockopt(
		socket_fd, ZSOCK_SOL_SOCKET, option,
		&timeout, sizeof(timeout)) == 0 ?
		0 : -errno;
}
#endif

int pqcp_tls_endpoint_handshake_bio(
	struct pqcp_tls_endpoint *endpoint,
	void *bio_context,
	mbedtls_ssl_send_t *send_callback,
	mbedtls_ssl_recv_t *receive_callback,
	mbedtls_ssl_recv_timeout_t *receive_timeout_callback,
	uint32_t timeout_ms)
{
	const int64_t deadline = k_uptime_get() + timeout_ms;
	int ret;

	if (endpoint == NULL || !endpoint->configured ||
	    bio_context == NULL || send_callback == NULL ||
	    (receive_callback == NULL &&
	     receive_timeout_callback == NULL) ||
	    timeout_ms == 0U) {
		return -EINVAL;
	}
	mbedtls_ssl_set_bio(
		&endpoint->ssl, bio_context, send_callback,
		receive_callback, receive_timeout_callback);
	mbedtls_ssl_conf_read_timeout(
		&endpoint->config, timeout_ms);
	for (;;) {
		ret = mbedtls_ssl_handshake(&endpoint->ssl);
		if (ret == 0) {
			endpoint->handshake_complete = true;
			return 0;
		}
		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		    ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			if (k_uptime_get() >= deadline) {
				return -ETIMEDOUT;
			}
			k_yield();
			continue;
		}
		if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
			return -ETIMEDOUT;
		}
		return -EIO;
	}
}

int pqcp_tls_endpoint_handshake(
	struct pqcp_tls_endpoint *endpoint,
	int socket_fd,
	bool owns_socket,
	uint32_t timeout_ms)
{
#if defined(CONFIG_PQCP_PROTECTED_CHANNEL_TCP)
	int ret;

	if (endpoint == NULL || !endpoint->configured ||
	    socket_fd < 0 || timeout_ms == 0U) {
		return -EINVAL;
	}
	endpoint->socket_fd = socket_fd;
	endpoint->owns_socket = owns_socket;
	ret = configure_socket_timeout(
		socket_fd, ZSOCK_SO_RCVTIMEO, timeout_ms);
	if (ret == 0) {
		ret = configure_socket_timeout(
			socket_fd, ZSOCK_SO_SNDTIMEO, timeout_ms);
	}
	if (ret != 0) {
		return ret;
	}
	return pqcp_tls_endpoint_handshake_bio(
		endpoint, &endpoint->socket_fd,
		endpoint_socket_send, endpoint_socket_receive,
		endpoint_socket_receive_timeout, timeout_ms);
#else
	ARG_UNUSED(endpoint);
	ARG_UNUSED(socket_fd);
	ARG_UNUSED(owns_socket);
	ARG_UNUSED(timeout_ms);
	return -ENOTSUP;
#endif
}

int pqcp_tls_endpoint_make_transport(
	struct pqcp_tls_endpoint *endpoint,
	struct pqcp_channel_transport *transport,
	struct pqcp_channel_mbedtls_context *adapter,
	uint32_t timeout_ms)
{
	if (endpoint == NULL || !endpoint->handshake_complete) {
		return -ENOTCONN;
	}
	return pqcp_channel_mbedtls_transport_init(
		transport, adapter, &endpoint->ssl,
		endpoint->socket_fd, timeout_ms, false);
}

void pqcp_tls_endpoint_free(
	struct pqcp_tls_endpoint *endpoint)
{
	if (endpoint == NULL) {
		return;
	}
	if (endpoint->handshake_complete) {
		(void)mbedtls_ssl_close_notify(&endpoint->ssl);
	}
	if (endpoint->owns_socket &&
	    endpoint->socket_fd >= 0) {
#if defined(CONFIG_PQCP_PROTECTED_CHANNEL_TCP)
		(void)zsock_close(endpoint->socket_fd);
#endif
	}
	mbedtls_ssl_free(&endpoint->ssl);
	mbedtls_ssl_config_free(&endpoint->config);
	pqcp_runtime_secure_zero(
		endpoint->psk, sizeof(endpoint->psk));
	pqcp_runtime_secure_zero(
		endpoint->identity,
		sizeof(endpoint->identity));
	memset(endpoint, 0, sizeof(*endpoint));
	endpoint->socket_fd = -1;
}
