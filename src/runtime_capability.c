/*
 * SPDX-License-Identifier: MIT
 *
 * Build-derived executable runtime capabilities.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/runtime.h>

#define PQCP_RUNTIME_OPERATION_MLKEM_KEYGEN (1U << 0)
#define PQCP_RUNTIME_OPERATION_MLKEM_ENCAPSULATE (1U << 1)
#define PQCP_RUNTIME_OPERATION_MLKEM_DECAPSULATE (1U << 2)
#define PQCP_RUNTIME_OPERATION_MLDSA_KEYGEN (1U << 3)
#define PQCP_RUNTIME_OPERATION_MLDSA_SIGN (1U << 4)
#define PQCP_RUNTIME_OPERATION_MLDSA_VERIFY (1U << 5)
#define PQCP_RUNTIME_OPERATION_PROTECTED_CHANNEL (1U << 6)
#define PQCP_RUNTIME_OPERATION_KNOWN_MASK ((1U << 7) - 1U)

#define PQCP_RUNTIME_KEY_BACKEND_VOLATILE_BIT (1U << 0)
#define PQCP_RUNTIME_KEY_BACKEND_PSA_BIT (1U << 1)
#define PQCP_RUNTIME_KEY_BACKEND_KNOWN_MASK ((1U << 2) - 1U)

static uint32_t current_operation_mask(void)
{
	uint32_t mask = 0U;

	if (IS_ENABLED(CONFIG_PQCP_MLKEM)) {
		mask |= PQCP_RUNTIME_OPERATION_MLKEM_KEYGEN |
			PQCP_RUNTIME_OPERATION_MLKEM_ENCAPSULATE |
			PQCP_RUNTIME_OPERATION_MLKEM_DECAPSULATE;
	}
	if (IS_ENABLED(CONFIG_PQCP_MLDSA)) {
		mask |= PQCP_RUNTIME_OPERATION_MLDSA_KEYGEN |
			PQCP_RUNTIME_OPERATION_MLDSA_SIGN |
			PQCP_RUNTIME_OPERATION_MLDSA_VERIFY;
	}
	if (IS_ENABLED(CONFIG_PQCP_PROTECTED_CHANNEL)) {
		mask |= PQCP_RUNTIME_OPERATION_PROTECTED_CHANNEL;
	}
	return mask;
}

static uint32_t current_key_backend_mask(void)
{
	uint32_t mask = 0U;

	if (IS_ENABLED(CONFIG_PQCP_RUNTIME_KEY_STORE_VOLATILE)) {
		mask |= PQCP_RUNTIME_KEY_BACKEND_VOLATILE_BIT;
	}
	if (IS_ENABLED(CONFIG_PQCP_RUNTIME_KEY_STORE_PSA)) {
		mask |= PQCP_RUNTIME_KEY_BACKEND_PSA_BIT;
	}
	return mask;
}

int pqcp_runtime_capability_current(
	struct pqcp_runtime_capability *capability)
{
	const struct pqcp_build_manifest *manifest;

	if (capability == NULL) {
		return -EINVAL;
	}
	manifest = pqcp_build_manifest_get();
	if (manifest == NULL ||
	    pqcp_build_manifest_validate(manifest) != 0) {
		return -EBADMSG;
	}
	memset(capability, 0, sizeof(*capability));
	capability->schema_version =
		PQCP_RUNTIME_SCHEMA_VERSION;
	capability->mlkem_level_mask =
		manifest->mlkem_level_mask;
	capability->mldsa_level_mask =
		manifest->mldsa_level_mask;
	capability->operation_mask =
		current_operation_mask();
	capability->key_backend_mask =
		current_key_backend_mask();
	capability->max_jobs =
		CONFIG_PQCP_RUNTIME_MAX_JOBS;
	capability->max_keys =
		CONFIG_PQCP_RUNTIME_MAX_KEYS;
	capability->workspace_bytes =
		CONFIG_PQCP_RUNTIME_WORKSPACE_BYTES;
	capability->executable_runtime =
		IS_ENABLED(CONFIG_PQCP_RUNTIME);
	capability->adaptive_integration =
		IS_ENABLED(CONFIG_PQCP_RUNTIME_ADAPTIVE_INTEGRATION);
	capability->protected_channel =
		IS_ENABLED(CONFIG_PQCP_PROTECTED_CHANNEL);
	capability->mutual_authentication =
		IS_ENABLED(CONFIG_PQCP_PROTECTED_CHANNEL_MUTUAL_AUTH);
	capability->psa_persistence_requested =
		IS_ENABLED(CONFIG_PQCP_RUNTIME_KEY_STORE_PSA);
	capability->psa_persistence_available = false;
	return pqcp_runtime_capability_validate(capability);
}

int pqcp_runtime_capability_validate(
	const struct pqcp_runtime_capability *capability)
{
	const uint32_t known_mlkem =
		PQCP_BUILD_MLKEM_LEVEL_512 |
		PQCP_BUILD_MLKEM_LEVEL_768 |
		PQCP_BUILD_MLKEM_LEVEL_1024;
	const uint32_t known_mldsa =
		PQCP_BUILD_MLDSA_LEVEL_44 |
		PQCP_BUILD_MLDSA_LEVEL_65 |
		PQCP_BUILD_MLDSA_LEVEL_87;

	if (capability == NULL ||
	    capability->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    (capability->mlkem_level_mask & ~known_mlkem) != 0U ||
	    (capability->mldsa_level_mask & ~known_mldsa) != 0U ||
	    (capability->operation_mask &
	     ~PQCP_RUNTIME_OPERATION_KNOWN_MASK) != 0U ||
	    (capability->key_backend_mask &
	     ~PQCP_RUNTIME_KEY_BACKEND_KNOWN_MASK) != 0U ||
	    capability->max_jobs == 0U ||
	    capability->max_keys == 0U ||
	    capability->workspace_bytes == 0U) {
		return -EINVAL;
	}
	if (capability->executable_runtime &&
	    capability->operation_mask == 0U) {
		return -EBADMSG;
	}
	if (capability->protected_channel &&
	    (capability->mlkem_level_mask == 0U ||
	     capability->mldsa_level_mask == 0U)) {
		return -EBADMSG;
	}
	if (capability->mutual_authentication &&
	    !capability->protected_channel) {
		return -EBADMSG;
	}
	if (capability->psa_persistence_available &&
	    !capability->psa_persistence_requested) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_runtime_capability_emit(
	const struct pqcp_runtime_capability *capability)
{
	int ret = pqcp_runtime_capability_validate(capability);

	if (ret != 0) {
		return ret;
	}
	printk("PQCP_RUNTIME_CAPABILITY schema=%u executable=%u adaptive=%u protected_channel=%u mutual_auth=%u mlkem_levels=0x%08x mldsa_levels=0x%08x operations=0x%08x key_backends=0x%08x max_jobs=%u max_keys=%u workspace=%u psa_requested=%u psa_available=%u\n",
	       capability->schema_version,
	       capability->executable_runtime ? 1U : 0U,
	       capability->adaptive_integration ? 1U : 0U,
	       capability->protected_channel ? 1U : 0U,
	       capability->mutual_authentication ? 1U : 0U,
	       capability->mlkem_level_mask,
	       capability->mldsa_level_mask,
	       capability->operation_mask,
	       capability->key_backend_mask,
	       capability->max_jobs,
	       capability->max_keys,
	       capability->workspace_bytes,
	       capability->psa_persistence_requested ? 1U : 0U,
	       capability->psa_persistence_available ? 1U : 0U);
	return 0;
}
