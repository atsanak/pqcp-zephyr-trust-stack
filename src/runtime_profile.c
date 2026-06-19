/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Build-derived adaptive profiles for the executable PQCP runtime.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include <pqcp_zephyr/build_manifest.h>
#include <pqcp_zephyr/runtime.h>

#include "runtime_internal.h"

struct profile_prior {
	uint64_t latency_us;
	uint64_t cycles;
	uint64_t ram_bytes;
	uint64_t stack_bytes;
	uint64_t heap_bytes;
	uint64_t flash_bytes;
	uint64_t energy_uj;
	uint32_t priority;
};

static const struct profile_prior prior_mlkem_512 = {
	.latency_us = 980U,
	.cycles = 980000U,
	.ram_bytes = 28672U,
	.stack_bytes = 9216U,
	.heap_bytes = 2048U,
	.flash_bytes = 54000U,
	.energy_uj = 850U,
	.priority = 660U,
};

static const struct profile_prior prior_mlkem_768 = {
	.latency_us = 1380U,
	.cycles = 1380000U,
	.ram_bytes = 32768U,
	.stack_bytes = 11264U,
	.heap_bytes = 2304U,
	.flash_bytes = 62000U,
	.energy_uj = 1120U,
	.priority = 820U,
};

static const struct profile_prior prior_mlkem_1024 = {
	.latency_us = 2050U,
	.cycles = 2050000U,
	.ram_bytes = 38912U,
	.stack_bytes = 14336U,
	.heap_bytes = 2560U,
	.flash_bytes = 72000U,
	.energy_uj = 1580U,
	.priority = 900U,
};

static const struct profile_prior prior_mldsa_44 = {
	.latency_us = 4200U,
	.cycles = 4200000U,
	.ram_bytes = 49152U,
	.stack_bytes = 16384U,
	.heap_bytes = 4096U,
	.flash_bytes = 98000U,
	.energy_uj = 3100U,
	.priority = 630U,
};

static const struct profile_prior prior_mldsa_65 = {
	.latency_us = 6900U,
	.cycles = 6900000U,
	.ram_bytes = 57344U,
	.stack_bytes = 20480U,
	.heap_bytes = 5120U,
	.flash_bytes = 116000U,
	.energy_uj = 4800U,
	.priority = 810U,
};

static const struct profile_prior prior_mldsa_87 = {
	.latency_us = 11200U,
	.cycles = 11200000U,
	.ram_bytes = 69632U,
	.stack_bytes = 26624U,
	.heap_bytes = 6144U,
	.flash_bytes = 142000U,
	.energy_uj = 7600U,
	.priority = 890U,
};

static uint32_t baseline_evidence(void)
{
	uint32_t evidence =
		PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
		PQCP_DEPLOYMENT_EVIDENCE_POLICY;

	if (IS_ENABLED(CONFIG_PQCP_KAT_BOOT_VERIFY)) {
		evidence |= PQCP_DEPLOYMENT_EVIDENCE_KAT;
	}
	if (IS_ENABLED(CONFIG_PQCP_ACVP)) {
		evidence |= PQCP_DEPLOYMENT_EVIDENCE_ACVP;
	}
	if (IS_ENABLED(CONFIG_PQCP_CT_SAMPLE_TRANSCRIPT)) {
		evidence |= PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE;
	}
	if (IS_ENABLED(CONFIG_QEMU_TARGET) ||
	    IS_ENABLED(CONFIG_ARCH_POSIX)) {
		evidence |= PQCP_DEPLOYMENT_EVIDENCE_SIMULATION;
	}
	return evidence;
}

static uint32_t kem_operations(void)
{
	return PQCP_DEPLOYMENT_OPERATION_MASK_KEM |
	       PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING |
	       PQCP_DEPLOYMENT_OPERATION_MASK_RECONNECT |
	       PQCP_DEPLOYMENT_OPERATION_MASK_TELEMETRY;
}

static uint32_t signature_operations(void)
{
	return PQCP_DEPLOYMENT_OPERATION_MASK_SIGNATURE |
	       PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING |
	       PQCP_DEPLOYMENT_OPERATION_MASK_FIRMWARE_UPDATE;
}

static uint32_t hybrid_operations(void)
{
	return kem_operations() |
	       signature_operations() |
	       PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS;
}

static void apply_prior(
	struct pqcp_adaptive_profile *profile,
	const struct profile_prior *prior)
{
	profile->nominal_latency_us = prior->latency_us;
	profile->nominal_cycles = prior->cycles;
	profile->ram_bytes = prior->ram_bytes;
	profile->stack_bytes = prior->stack_bytes;
	profile->heap_bytes = prior->heap_bytes;
	profile->flash_bytes = prior->flash_bytes;
	profile->energy_uj = prior->energy_uj;
	profile->priority = prior->priority;
	profile->latency_source =
		PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR;
	profile->cycles_source =
		PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR;
	profile->memory_source =
		PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR;
	profile->energy_source =
		PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR;
	profile->observation_count = 0U;
}

static int initialize_profile(
	struct pqcp_adaptive_profile *profile,
	const char *profile_id,
	enum pqcp_deployment_candidate_kind kind,
	uint32_t mlkem_level,
	uint32_t mldsa_level,
	uint32_t operation_mask,
	const struct profile_prior *prior)
{
	if (profile == NULL || profile_id == NULL ||
	    prior == NULL) {
		return -EINVAL;
	}
	memset(profile, 0, sizeof(*profile));
	profile->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	profile->kind = kind;
	profile->operation_mask = operation_mask;
	profile->mlkem_level = mlkem_level;
	profile->mldsa_level = mldsa_level;
	profile->security_level =
		pqcp_runtime_internal_security_level(
			mlkem_level, mldsa_level);
	profile->evidence_mask = baseline_evidence();
	profile->enabled = true;
	profile->native_provider = true;
	profile->production_allowed = true;
	profile->hardware_validated = false;
	profile->hybrid_required =
		kind == PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE;
	apply_prior(profile, prior);
	return pqcp_runtime_internal_copy_text(
		profile->profile_id,
		sizeof(profile->profile_id),
		profile_id);
}

static const struct profile_prior *kem_prior(uint32_t level)
{
	switch (level) {
	case PQCP_MLKEM_512:
		return &prior_mlkem_512;
	case PQCP_MLKEM_768:
		return &prior_mlkem_768;
	case PQCP_MLKEM_1024:
		return &prior_mlkem_1024;
	default:
		return NULL;
	}
}

static const struct profile_prior *signature_prior(uint32_t level)
{
	switch (level) {
	case PQCP_MLDSA_44:
		return &prior_mldsa_44;
	case PQCP_MLDSA_65:
		return &prior_mldsa_65;
	case PQCP_MLDSA_87:
		return &prior_mldsa_87;
	default:
		return NULL;
	}
}

static struct profile_prior combine_priors(
	const struct profile_prior *kem,
	const struct profile_prior *signature)
{
	struct profile_prior combined = {
		.latency_us =
			kem->latency_us + signature->latency_us,
		.cycles = kem->cycles + signature->cycles,
		.ram_bytes = kem->ram_bytes + signature->ram_bytes,
		.stack_bytes =
			kem->stack_bytes + signature->stack_bytes,
		.heap_bytes = kem->heap_bytes + signature->heap_bytes,
		.flash_bytes =
			kem->flash_bytes + signature->flash_bytes,
		.energy_uj = kem->energy_uj + signature->energy_uj,
		.priority =
			(kem->priority + signature->priority) / 2U,
	};

	return combined;
}

static int add_kem_profile(
	struct pqcp_adaptive_profile_registry *registry,
	uint32_t level)
{
	struct pqcp_adaptive_profile profile;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	int written;

	written = snprintf(
		profile_id, sizeof(profile_id),
		"mlkem%u-runtime", level);
	if (written <= 0 || (size_t)written >= sizeof(profile_id)) {
		return -ENOSPC;
	}
	if (initialize_profile(
		    &profile, profile_id,
		    PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		    level, 0U, kem_operations(),
		    kem_prior(level)) != 0) {
		return -EINVAL;
	}
	return pqcp_adaptive_profile_registry_add(
		registry, &profile);
}

static int add_signature_profile(
	struct pqcp_adaptive_profile_registry *registry,
	uint32_t level)
{
	struct pqcp_adaptive_profile profile;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	int written;

	written = snprintf(
		profile_id, sizeof(profile_id),
		"mldsa%u-runtime", level);
	if (written <= 0 || (size_t)written >= sizeof(profile_id)) {
		return -ENOSPC;
	}
	if (initialize_profile(
		    &profile, profile_id,
		    PQCP_DEPLOYMENT_CANDIDATE_MLDSA,
		    0U, level, signature_operations(),
		    signature_prior(level)) != 0) {
		return -EINVAL;
	}
	return pqcp_adaptive_profile_registry_add(
		registry, &profile);
}

static int add_hybrid_profile(
	struct pqcp_adaptive_profile_registry *registry,
	uint32_t mlkem_level,
	uint32_t mldsa_level)
{
	struct pqcp_adaptive_profile profile;
	const struct profile_prior *kem =
		kem_prior(mlkem_level);
	const struct profile_prior *signature =
		signature_prior(mldsa_level);
	struct profile_prior combined;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
	int written;

	if (kem == NULL || signature == NULL) {
		return -EINVAL;
	}
	combined = combine_priors(kem, signature);
	written = snprintf(
		profile_id, sizeof(profile_id),
		"hybrid%u-%u-runtime",
		mlkem_level, mldsa_level);
	if (written <= 0 || (size_t)written >= sizeof(profile_id)) {
		return -ENOSPC;
	}
	if (initialize_profile(
		    &profile, profile_id,
		    PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE,
		    mlkem_level, mldsa_level,
		    hybrid_operations(), &combined) != 0) {
		return -EINVAL;
	}
	return pqcp_adaptive_profile_registry_add(
		registry, &profile);
}

static bool mlkem_enabled(uint32_t mask, uint32_t level)
{
	switch (level) {
	case PQCP_MLKEM_512:
		return (mask & PQCP_BUILD_MLKEM_LEVEL_512) != 0U;
	case PQCP_MLKEM_768:
		return (mask & PQCP_BUILD_MLKEM_LEVEL_768) != 0U;
	case PQCP_MLKEM_1024:
		return (mask & PQCP_BUILD_MLKEM_LEVEL_1024) != 0U;
	default:
		return false;
	}
}

static bool mldsa_enabled(uint32_t mask, uint32_t level)
{
	switch (level) {
	case PQCP_MLDSA_44:
		return (mask & PQCP_BUILD_MLDSA_LEVEL_44) != 0U;
	case PQCP_MLDSA_65:
		return (mask & PQCP_BUILD_MLDSA_LEVEL_65) != 0U;
	case PQCP_MLDSA_87:
		return (mask & PQCP_BUILD_MLDSA_LEVEL_87) != 0U;
	default:
		return false;
	}
}

int pqcp_runtime_profile_registry_build(
	struct pqcp_adaptive_profile_registry *registry)
{
	static const uint32_t kem_levels[] = {
		PQCP_MLKEM_512,
		PQCP_MLKEM_768,
		PQCP_MLKEM_1024,
	};
	static const uint32_t signature_levels[] = {
		PQCP_MLDSA_44,
		PQCP_MLDSA_65,
		PQCP_MLDSA_87,
	};
	const struct pqcp_build_manifest *manifest;
	int ret;

	if (registry == NULL) {
		return -EINVAL;
	}
	manifest = pqcp_build_manifest_get();
	if (manifest == NULL ||
	    pqcp_build_manifest_validate(manifest) != 0) {
		return -EBADMSG;
	}
	ret = pqcp_adaptive_profile_registry_init(registry);
	if (ret != 0) {
		return ret;
	}
	for (size_t index = 0U;
	     index < sizeof(kem_levels) / sizeof(kem_levels[0]);
	     ++index) {
		if (!mlkem_enabled(
			    manifest->mlkem_level_mask,
			    kem_levels[index])) {
			continue;
		}
		ret = add_kem_profile(registry, kem_levels[index]);
		if (ret != 0) {
			return ret;
		}
	}
	for (size_t index = 0U;
	     index < sizeof(signature_levels) /
			     sizeof(signature_levels[0]);
	     ++index) {
		if (!mldsa_enabled(
			    manifest->mldsa_level_mask,
			    signature_levels[index])) {
			continue;
		}
		ret = add_signature_profile(
			registry, signature_levels[index]);
		if (ret != 0) {
			return ret;
		}
	}
	for (size_t kem_index = 0U;
	     kem_index < sizeof(kem_levels) / sizeof(kem_levels[0]);
	     ++kem_index) {
		if (!mlkem_enabled(
			    manifest->mlkem_level_mask,
			    kem_levels[kem_index])) {
			continue;
		}
		for (size_t sig_index = 0U;
		     sig_index < sizeof(signature_levels) /
				     sizeof(signature_levels[0]);
		     ++sig_index) {
			if (!mldsa_enabled(
				    manifest->mldsa_level_mask,
				    signature_levels[sig_index])) {
				continue;
			}
			if (pqcp_runtime_internal_security_level(
				    kem_levels[kem_index],
				    signature_levels[sig_index]) !=
			    pqcp_runtime_internal_security_level(
				    kem_levels[kem_index], 0U)) {
				continue;
			}
			ret = add_hybrid_profile(
				registry,
				kem_levels[kem_index],
				signature_levels[sig_index]);
			if (ret != 0) {
				return ret;
			}
		}
	}
	if (registry->count == 0U) {
		return -ENOTSUP;
	}
	return pqcp_adaptive_profile_registry_validate(registry);
}
