/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Direct mbedTLS adapter. Zephyr TLS sockets are intentionally not used
 * because they do not expose TLS exporter material to the application.
 */

#include <errno.h>
#include <string.h>

#include <mbedtls/error.h>
#include <mbedtls/ssl.h>

#include <zephyr/kernel.h>

#if defined(CONFIG_NET_SOCKETS)
#include <zephyr/net/socket.h>
#endif

#include <pqcp_zephyr/protected_channel_mbedtls.h>

static struct pqcp_channel_mbedtls_context *adapter_context(
	void *context)
{
	return context;
}

static int ssl_error_to_errno(int error)
{
	switch (error) {
	case MBEDTLS_ERR_SSL_WANT_READ:
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		return -EAGAIN;
	case MBEDTLS_ERR_SSL_TIMEOUT:
		return -ETIMEDOUT;
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		return -ECONNRESET;
	case MBEDTLS_ERR_SSL_BAD_INPUT_DATA:
		return -EINVAL;
	default:
		return -EIO;
	}
}

static int set_socket_timeout(
	int socket_fd,
	int option,
	uint32_t timeout_ms)
{
#if defined(CONFIG_NET_SOCKETS)
	struct timeval timeout = {
		.tv_sec = timeout_ms / 1000U,
		.tv_usec = (timeout_ms % 1000U) * 1000U,
	};
#endif

	if (socket_fd < 0 || timeout_ms == 0U) {
		return 0;
	}
#if defined(CONFIG_NET_SOCKETS)
	return zsock_setsockopt(
		socket_fd, ZSOCK_SOL_SOCKET, option,
		&timeout, sizeof(timeout)) == 0 ?
		0 : -errno;
#else
	ARG_UNUSED(option);
	return -ENOTSUP;
#endif
}

int pqcp_channel_mbedtls_transport_init(
	struct pqcp_channel_transport *transport,
	struct pqcp_channel_mbedtls_context *context,
	mbedtls_ssl_context *ssl,
	int socket_fd,
	uint32_t default_timeout_ms,
	bool owns_socket)
{
	if (transport == NULL || context == NULL ||
	    ssl == NULL || socket_fd < -1 ||
	    default_timeout_ms == 0U) {
		return -EINVAL;
	}
	memset(context, 0, sizeof(*context));
	context->ssl = ssl;
	context->socket_fd = socket_fd;
	context->default_timeout_ms = default_timeout_ms;
	context->owns_socket = owns_socket;
	context->handshake_complete =
		mbedtls_ssl_is_handshake_over(ssl);
	if (!context->handshake_complete) {
		return -ENOTCONN;
	}
	memset(transport, 0, sizeof(*transport));
	transport->context = context;
	transport->send = pqcp_channel_mbedtls_send;
	transport->receive = pqcp_channel_mbedtls_receive;
	transport->export_keying_material =
		pqcp_channel_mbedtls_export;
	transport->close = pqcp_channel_mbedtls_close;
	return 0;
}

int pqcp_channel_mbedtls_send(
	void *context,
	const uint8_t *buffer,
	size_t length,
	uint32_t timeout_ms)
{
	struct pqcp_channel_mbedtls_context *adapter =
		adapter_context(context);
	size_t offset = 0U;
	int64_t deadline;
	int ret;

	if (adapter == NULL || adapter->ssl == NULL ||
	    !adapter->handshake_complete ||
	    (buffer == NULL && length != 0U)) {
		return -EINVAL;
	}
	if (timeout_ms == 0U) {
		timeout_ms = adapter->default_timeout_ms;
	}
	deadline = k_uptime_get() + timeout_ms;
#if defined(CONFIG_NET_SOCKETS)
	ret = set_socket_timeout(
		adapter->socket_fd, ZSOCK_SO_SNDTIMEO,
		timeout_ms);
#else
	ret = set_socket_timeout(
		adapter->socket_fd, 0, timeout_ms);
#endif
	if (ret != 0) {
		return ret;
	}
	while (offset < length) {
		ret = mbedtls_ssl_write(
			adapter->ssl, buffer + offset,
			length - offset);
		if (ret > 0) {
			offset += (size_t)ret;
			continue;
		}
		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		    ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			if (k_uptime_get() >= deadline) {
				return -ETIMEDOUT;
			}
			k_yield();
			continue;
		}
		return ssl_error_to_errno(ret);
	}
	return 0;
}

int pqcp_channel_mbedtls_receive(
	void *context,
	uint8_t *buffer,
	size_t capacity,
	size_t *received,
	uint32_t timeout_ms)
{
	struct pqcp_channel_mbedtls_context *adapter =
		adapter_context(context);
	int64_t deadline;
	int ret;

	if (adapter == NULL || adapter->ssl == NULL ||
	    !adapter->handshake_complete || buffer == NULL ||
	    capacity == 0U || received == NULL) {
		return -EINVAL;
	}
	if (timeout_ms == 0U) {
		timeout_ms = adapter->default_timeout_ms;
	}
	deadline = k_uptime_get() + timeout_ms;
#if defined(CONFIG_NET_SOCKETS)
	ret = set_socket_timeout(
		adapter->socket_fd, ZSOCK_SO_RCVTIMEO,
		timeout_ms);
#else
	ret = set_socket_timeout(
		adapter->socket_fd, 0, timeout_ms);
#endif
	if (ret != 0) {
		return ret;
	}
	for (;;) {
		ret = mbedtls_ssl_read(
			adapter->ssl, buffer, capacity);
		if (ret > 0) {
			*received = (size_t)ret;
			return 0;
		}
		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		    ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			if (k_uptime_get() >= deadline) {
				*received = 0U;
				return -ETIMEDOUT;
			}
			k_yield();
			continue;
		}
		*received = 0U;
		return ssl_error_to_errno(ret);
	}
}

// cppcheck-suppress constParameterCallback
// cppcheck-suppress constParameter
int pqcp_channel_mbedtls_export(
	void *context,
	const char *label,
	const uint8_t *export_context,
	size_t export_context_length,
	// cppcheck-suppress constParameterCallback
	// cppcheck-suppress constParameter
	uint8_t *output,
	size_t output_length)
{
	const struct pqcp_channel_mbedtls_context *adapter =
		adapter_context(context);
	int ret;

	if (adapter == NULL || adapter->ssl == NULL ||
	    !adapter->handshake_complete || label == NULL ||
	    output == NULL || output_length == 0U ||
	    (export_context == NULL &&
	     export_context_length != 0U)) {
		return -EINVAL;
	}
#if defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
	ret = mbedtls_ssl_export_keying_material(
		adapter->ssl, output, output_length,
		label, strlen(label), export_context,
		export_context_length, 1);
	return ret == 0 ? 0 : ssl_error_to_errno(ret);
#else
	ARG_UNUSED(ret);
	return -ENOTSUP;
#endif
}

int pqcp_channel_mbedtls_close(void *context)
{
	struct pqcp_channel_mbedtls_context *adapter =
		adapter_context(context);
	int result = 0;

	if (adapter == NULL) {
		return -EINVAL;
	}
	if (adapter->ssl != NULL &&
	    adapter->handshake_complete) {
		int ret;

		do {
			ret = mbedtls_ssl_close_notify(adapter->ssl);
		} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
		if (ret != 0 &&
		    ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			result = ssl_error_to_errno(ret);
		}
	}
	if (adapter->owns_socket && adapter->socket_fd >= 0) {
#if defined(CONFIG_NET_SOCKETS)
		if (zsock_close(adapter->socket_fd) != 0 &&
		    result == 0) {
			result = -errno;
		}
#else
		if (result == 0) {
			result = -ENOTSUP;
		}
#endif
		adapter->socket_fd = -1;
	}
	adapter->handshake_complete = false;
	return result;
}
