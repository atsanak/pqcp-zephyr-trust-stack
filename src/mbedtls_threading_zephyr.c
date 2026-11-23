/* SPDX-License-Identifier: MIT */
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <mbedtls/threading.h>

static int mutex_init(mbedtls_platform_mutex_t *mutex)
{
	return k_mutex_init(mutex) == 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static void mutex_free(mbedtls_platform_mutex_t *mutex)
{
	/* Zephyr mutexes own no dynamic resources. Caller excludes waiters. */
	ARG_UNUSED(mutex);
}

static int mutex_lock(mbedtls_platform_mutex_t *mutex)
{
	return k_mutex_lock(mutex, K_FOREVER) == 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static int mutex_unlock(mbedtls_platform_mutex_t *mutex)
{
	return k_mutex_unlock(mutex) == 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static int cond_init(mbedtls_platform_condition_variable_t *cond)
{
	return k_condvar_init(cond) == 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static void cond_free(mbedtls_platform_condition_variable_t *cond)
{
	/* No heap ownership; destroying a condition with waiters is invalid. */
	ARG_UNUSED(cond);
}

static int cond_signal(mbedtls_platform_condition_variable_t *cond)
{
	return k_condvar_signal(cond) >= 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static int cond_broadcast(mbedtls_platform_condition_variable_t *cond)
{
	return k_condvar_broadcast(cond) >= 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static int cond_wait(mbedtls_platform_condition_variable_t *cond,
	mbedtls_platform_mutex_t *mutex)
{
	return k_condvar_wait(cond, mutex, K_FOREVER) == 0 ? 0 : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static int install_threading_port(void)
{
	/* Only initializes kernel objects here: no waiting or heap allocation.
	 * Zephyr's Mbed TLS heap and PSA initialization runs at POST_KERNEL.
	 */
	mbedtls_threading_set_alt(mutex_init, mutex_free, mutex_lock, mutex_unlock,
		cond_init, cond_free, cond_signal, cond_broadcast, cond_wait);
	return 0;
}

SYS_INIT(install_threading_port, PRE_KERNEL_2, 0);
