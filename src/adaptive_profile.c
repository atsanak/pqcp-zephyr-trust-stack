/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Compiled-profile registry for adaptive PQC deployment.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

#include <pqcp_zephyr/adaptive_control.h>
#include <pqcp_zephyr/runtime.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_PROFILE_DOMAIN UINT64_C(0x41445050524f4649)

static uint32_t baseline_evidence(void)
{
	return PQCP_DEPLOYMENT_EVIDENCE_KAT |
	       PQCP_DEPLOYMENT_EVIDENCE_ACVP |
	       PQCP_DEPLOYMENT_EVIDENCE_CT_SMOKE |
	       PQCP_DEPLOYMENT_EVIDENCE_REPRODUCIBLE |
	       PQCP_DEPLOYMENT_EVIDENCE_BASELINE |
	       PQCP_DEPLOYMENT_EVIDENCE_SIMULATION |
	       PQCP_DEPLOYMENT_EVIDENCE_POLICY |
	       PQCP_DEPLOYMENT_EVIDENCE_PROVIDER |
	       PQCP_DEPLOYMENT_EVIDENCE_TRANSCRIPT |
	       PQCP_DEPLOYMENT_EVIDENCE_RESOURCE |
	       PQCP_DEPLOYMENT_EVIDENCE_PERFORMANCE;
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
	return PQCP_DEPLOYMENT_OPERATION_MASK_KEM |
	       PQCP_DEPLOYMENT_OPERATION_MASK_SIGNATURE |
	       PQCP_DEPLOYMENT_OPERATION_MASK_HYBRID_TLS |
	       PQCP_DEPLOYMENT_OPERATION_MASK_ONBOARDING |
	       PQCP_DEPLOYMENT_OPERATION_MASK_RECONNECT |
	       PQCP_DEPLOYMENT_OPERATION_MASK_FIRMWARE_UPDATE |
	       PQCP_DEPLOYMENT_OPERATION_MASK_TELEMETRY;
}

static struct pqcp_adaptive_profile make_mlkem_profile(
	const char *profile_id,
	uint32_t level,
	uint32_t security_level,
	uint64_t latency_us,
	uint64_t cycles,
	uint64_t ram_bytes,
	uint64_t stack_bytes,
	uint64_t heap_bytes,
	uint64_t flash_bytes,
	uint64_t energy_uj,
	uint32_t priority)
{
	struct pqcp_adaptive_profile profile = {
		.schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION,
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLKEM,
		.operation_mask = kem_operations(),
		.security_level = security_level,
		.mlkem_level = level,
		.mldsa_level = 0U,
		.nominal_latency_us = latency_us,
		.nominal_cycles = cycles,
		.ram_bytes = ram_bytes,
		.stack_bytes = stack_bytes,
		.heap_bytes = heap_bytes,
		.flash_bytes = flash_bytes,
		.energy_uj = energy_uj,
		.latency_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.cycles_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.memory_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.energy_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.observation_count = 0U,
		.evidence_mask = baseline_evidence(),
		.priority = priority,
		.enabled = true,
		.native_provider = true,
		.production_allowed = true,
		.hardware_validated = false,
		.hybrid_required = false,
	};

	pqcp_adaptive_internal_set_text(
		profile.profile_id, sizeof(profile.profile_id), profile_id);
	return profile;
}

static struct pqcp_adaptive_profile make_mldsa_profile(
	const char *profile_id,
	uint32_t level,
	uint32_t security_level,
	uint64_t latency_us,
	uint64_t cycles,
	uint64_t ram_bytes,
	uint64_t stack_bytes,
	uint64_t heap_bytes,
	uint64_t flash_bytes,
	uint64_t energy_uj,
	uint32_t priority)
{
	struct pqcp_adaptive_profile profile = {
		.schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION,
		.kind = PQCP_DEPLOYMENT_CANDIDATE_MLDSA,
		.operation_mask = signature_operations(),
		.security_level = security_level,
		.mlkem_level = 0U,
		.mldsa_level = level,
		.nominal_latency_us = latency_us,
		.nominal_cycles = cycles,
		.ram_bytes = ram_bytes,
		.stack_bytes = stack_bytes,
		.heap_bytes = heap_bytes,
		.flash_bytes = flash_bytes,
		.energy_uj = energy_uj,
		.latency_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.cycles_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.memory_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.energy_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.observation_count = 0U,
		.evidence_mask = baseline_evidence(),
		.priority = priority,
		.enabled = true,
		.native_provider = true,
		.production_allowed = true,
		.hardware_validated = false,
		.hybrid_required = false,
	};

	pqcp_adaptive_internal_set_text(
		profile.profile_id, sizeof(profile.profile_id), profile_id);
	return profile;
}

static struct pqcp_adaptive_profile make_hybrid_profile(
	const char *profile_id,
	uint32_t mlkem_level,
	uint32_t mldsa_level,
	uint32_t security_level,
	uint64_t latency_us,
	uint64_t cycles,
	uint64_t ram_bytes,
	uint64_t stack_bytes,
	uint64_t heap_bytes,
	uint64_t flash_bytes,
	uint64_t energy_uj,
	uint32_t priority)
{
	struct pqcp_adaptive_profile profile = {
		.schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION,
		.kind = PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE,
		.operation_mask = hybrid_operations(),
		.security_level = security_level,
		.mlkem_level = mlkem_level,
		.mldsa_level = mldsa_level,
		.nominal_latency_us = latency_us,
		.nominal_cycles = cycles,
		.ram_bytes = ram_bytes,
		.stack_bytes = stack_bytes,
		.heap_bytes = heap_bytes,
		.flash_bytes = flash_bytes,
		.energy_uj = energy_uj,
		.latency_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.cycles_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.memory_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.energy_source = PQCP_ADAPTIVE_METRIC_BOOTSTRAP_PRIOR,
		.observation_count = 0U,
		.evidence_mask = baseline_evidence(),
		.priority = priority,
		.enabled = true,
		.native_provider = true,
		.production_allowed = true,
		.hardware_validated = false,
		.hybrid_required = true,
	};

	pqcp_adaptive_internal_set_text(
		profile.profile_id, sizeof(profile.profile_id), profile_id);
	return profile;
}

static void registry_recount(struct pqcp_adaptive_profile_registry *registry)
{
	uint32_t enabled = 0U;
	uint32_t native = 0U;
	uint32_t production = 0U;

	for (uint32_t index = 0U; index < registry->count; ++index) {
		const struct pqcp_adaptive_profile *profile =
			&registry->profiles[index];

		if (profile->enabled) {
			enabled++;
		}
		if (profile->native_provider) {
			native++;
		}
		if (profile->production_allowed) {
			production++;
		}
	}
	registry->enabled_count = enabled;
	registry->native_count = native;
	registry->production_count = production;
}

static int registry_refresh_digest(
	struct pqcp_adaptive_profile_registry *registry)
{
	if (registry == NULL) {
		return -EINVAL;
	}
	registry_recount(registry);
	return pqcp_adaptive_internal_digest_registry(
		registry, registry->registry_digest_hex);
}

static int registry_find_index(
	const struct pqcp_adaptive_profile_registry *registry,
	const char *profile_id,
	uint32_t *index)
{
	if (registry == NULL ||
	    !pqcp_adaptive_internal_id_valid(profile_id)) {
		return -EINVAL;
	}
	for (uint32_t current = 0U;
	     current < registry->count; ++current) {
		const int comparison = strcmp(
			registry->profiles[current].profile_id, profile_id);

		if (comparison == 0) {
			if (index != NULL) {
				*index = current;
			}
			return 0;
		}
		if (comparison > 0) {
			break;
		}
	}
	return -ENOENT;
}

static uint32_t registry_insert_index(
	const struct pqcp_adaptive_profile_registry *registry,
	const char *profile_id)
{
	for (uint32_t index = 0U; index < registry->count; ++index) {
		if (strcmp(registry->profiles[index].profile_id,
			   profile_id) > 0) {
			return index;
		}
	}
	return registry->count;
}

static void registry_shift_right(
	struct pqcp_adaptive_profile_registry *registry,
	uint32_t start)
{
	for (uint32_t index = registry->count; index > start; --index) {
		registry->profiles[index] = registry->profiles[index - 1U];
	}
}

static void registry_shift_left(
	struct pqcp_adaptive_profile_registry *registry,
	uint32_t start)
{
	for (uint32_t index = start;
	     index + 1U < registry->count; ++index) {
		registry->profiles[index] = registry->profiles[index + 1U];
	}
	if (registry->count != 0U) {
		memset(&registry->profiles[registry->count - 1U], 0,
		       sizeof(registry->profiles[0]));
	}
}

static int registry_validate_order(
	const struct pqcp_adaptive_profile_registry *registry)
{
	for (uint32_t index = 0U; index < registry->count; ++index) {
		if (!pqcp_adaptive_internal_profile_valid(
			    &registry->profiles[index])) {
			return -EINVAL;
		}
		if (index != 0U &&
		    strcmp(registry->profiles[index - 1U].profile_id,
			   registry->profiles[index].profile_id) >= 0) {
			return -EEXIST;
		}
	}
	return 0;
}

static int registry_validate_counts(
	const struct pqcp_adaptive_profile_registry *registry)
{
	uint32_t enabled = 0U;
	uint32_t native = 0U;
	uint32_t production = 0U;

	for (uint32_t index = 0U; index < registry->count; ++index) {
		const struct pqcp_adaptive_profile *profile =
			&registry->profiles[index];

		enabled += profile->enabled ? 1U : 0U;
		native += profile->native_provider ? 1U : 0U;
		production += profile->production_allowed ? 1U : 0U;
	}
	if (enabled != registry->enabled_count ||
	    native != registry->native_count ||
	    production != registry->production_count) {
		return -EBADMSG;
	}
	return 0;
}

static int registry_validate_digest(
	const struct pqcp_adaptive_profile_registry *registry)
{
	char expected[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];
	int ret;

	ret = pqcp_adaptive_internal_digest_registry(registry, expected);
	if (ret != 0) {
		return ret;
	}
	if (strcmp(expected, registry->registry_digest_hex) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_adaptive_profile_registry_init(
	struct pqcp_adaptive_profile_registry *registry)
{
	if (registry == NULL) {
		return -EINVAL;
	}
	memset(registry, 0, sizeof(*registry));
	registry->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	return registry_refresh_digest(registry);
}

int pqcp_adaptive_profile_registry_add(
	struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_profile *profile)
{
	uint32_t insertion;

	if (registry == NULL ||
	    registry->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_profile_valid(profile)) {
		return -EINVAL;
	}
	if (registry->count >= PQCP_ADAPTIVE_MAX_PROFILES) {
		return -ENOSPC;
	}
	if (registry_find_index(registry, profile->profile_id, NULL) == 0) {
		return -EEXIST;
	}
	insertion = registry_insert_index(registry, profile->profile_id);
	registry_shift_right(registry, insertion);
	registry->profiles[insertion] = *profile;
	registry->count++;
	return registry_refresh_digest(registry);
}

int pqcp_adaptive_profile_registry_remove(
	struct pqcp_adaptive_profile_registry *registry,
	const char *profile_id)
{
	uint32_t index;
	int ret;

	if (registry == NULL ||
	    registry->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	ret = registry_find_index(registry, profile_id, &index);
	if (ret != 0) {
		return ret;
	}
	registry_shift_left(registry, index);
	registry->count--;
	return registry_refresh_digest(registry);
}

int pqcp_adaptive_profile_registry_enable(
	struct pqcp_adaptive_profile_registry *registry,
	const char *profile_id,
	bool enabled)
{
	uint32_t index;
	int ret;

	if (registry == NULL ||
	    registry->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION) {
		return -EINVAL;
	}
	ret = registry_find_index(registry, profile_id, &index);
	if (ret != 0) {
		return ret;
	}
	if (!enabled && registry->profiles[index].production_allowed) {
		registry->profiles[index].production_allowed = false;
	}
	registry->profiles[index].enabled = enabled;
	return registry_refresh_digest(registry);
}

const struct pqcp_adaptive_profile *pqcp_adaptive_profile_registry_find(
	const struct pqcp_adaptive_profile_registry *registry,
	const char *profile_id)
{
	uint32_t index;

	if (registry_find_index(registry, profile_id, &index) != 0) {
		return NULL;
	}
	return &registry->profiles[index];
}

static int add_default_kem_profiles(
	struct pqcp_adaptive_profile_registry *registry)
{
	const struct pqcp_adaptive_profile profiles[] = {
		make_mlkem_profile("mlkem512-balanced", 512U, 1U,
				   980U, 980000U, 28672U, 9216U,
				   2048U, 54000U, 850U, 660U),
		make_mlkem_profile("mlkem768-balanced", 768U, 3U,
				   1380U, 1380000U, 32768U, 11264U,
				   2304U, 62000U, 1120U, 820U),
		make_mlkem_profile("mlkem1024-conservative", 1024U, 5U,
				   2050U, 2050000U, 38912U, 14336U,
				   2560U, 72000U, 1580U, 900U),
	};

	for (size_t index = 0U;
	     index < sizeof(profiles) / sizeof(profiles[0]); ++index) {
		const int ret = pqcp_adaptive_profile_registry_add(
			registry, &profiles[index]);

		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

static int add_default_signature_profiles(
	struct pqcp_adaptive_profile_registry *registry)
{
	const struct pqcp_adaptive_profile profiles[] = {
		make_mldsa_profile("mldsa44-compact", 44U, 2U,
				   4200U, 4200000U, 49152U, 16384U,
				   4096U, 98000U, 3100U, 630U),
		make_mldsa_profile("mldsa65-balanced", 65U, 3U,
				   6900U, 6900000U, 57344U, 20480U,
				   5120U, 116000U, 4800U, 810U),
		make_mldsa_profile("mldsa87-conservative", 87U, 5U,
				   11200U, 11200000U, 69632U, 26624U,
				   6144U, 142000U, 7600U, 890U),
	};

	for (size_t index = 0U;
	     index < sizeof(profiles) / sizeof(profiles[0]); ++index) {
		const int ret = pqcp_adaptive_profile_registry_add(
			registry, &profiles[index]);

		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

static int add_default_hybrid_profiles(
	struct pqcp_adaptive_profile_registry *registry)
{
	const struct pqcp_adaptive_profile profiles[] = {
		make_hybrid_profile("hybrid512-44-compact",
				    512U, 44U, 2U, 5600U, 5600000U,
				    77824U, 23552U, 7168U, 154000U,
				    4300U, 650U),
		make_hybrid_profile("hybrid768-65-balanced",
				    768U, 65U, 3U, 8500U, 8500000U,
				    90112U, 28672U, 8192U, 178000U,
				    6300U, 850U),
		make_hybrid_profile("hybrid1024-87-critical",
				    1024U, 87U, 5U, 13600U, 13600000U,
				    108544U, 35840U, 9216U, 214000U,
				    9800U, 930U),
	};

	for (size_t index = 0U;
	     index < sizeof(profiles) / sizeof(profiles[0]); ++index) {
		const int ret = pqcp_adaptive_profile_registry_add(
			registry, &profiles[index]);

		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

int pqcp_adaptive_profile_registry_default(
	struct pqcp_adaptive_profile_registry *registry)
{
	int ret;

	if (IS_ENABLED(CONFIG_PQCP_RUNTIME)) {
		return pqcp_runtime_profile_registry_build(registry);
	}
	ret = pqcp_adaptive_profile_registry_init(registry);
	if (ret != 0) {
		return ret;
	}
	ret = add_default_kem_profiles(registry);
	if (ret != 0) {
		return ret;
	}
	ret = add_default_signature_profiles(registry);
	if (ret != 0) {
		return ret;
	}
	ret = add_default_hybrid_profiles(registry);
	if (ret != 0) {
		return ret;
	}
	return pqcp_adaptive_profile_registry_validate(registry);
}

int pqcp_adaptive_profile_registry_validate(
	const struct pqcp_adaptive_profile_registry *registry)
{
	int ret;

	if (registry == NULL ||
	    registry->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    registry->count > PQCP_ADAPTIVE_MAX_PROFILES ||
	    registry->enabled_count > registry->count ||
	    registry->native_count > registry->count ||
	    registry->production_count > registry->count) {
		return -EINVAL;
	}
	ret = registry_validate_order(registry);
	if (ret != 0) {
		return ret;
	}
	ret = registry_validate_counts(registry);
	if (ret != 0) {
		return ret;
	}
	return registry_validate_digest(registry);
}

static const char *profile_kind_str(
	enum pqcp_deployment_candidate_kind kind)
{
	switch (kind) {
	case PQCP_DEPLOYMENT_CANDIDATE_MLKEM:
		return "ML-KEM";
	case PQCP_DEPLOYMENT_CANDIDATE_MLDSA:
		return "ML-DSA";
	case PQCP_DEPLOYMENT_CANDIDATE_HYBRID_SUITE:
		return "HYBRID";
	default:
		return "INVALID";
	}
}

static int profile_digest_hex(
	const struct pqcp_adaptive_profile *profile,
	char output[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U])
{
	struct pqcp_deployment_evidence_digest digest;
	int ret;

	if (!pqcp_adaptive_internal_profile_valid(profile) ||
	    output == NULL) {
		return -EINVAL;
	}
	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_PROFILE_DOMAIN);
	ret = pqcp_adaptive_internal_digest_profile(profile, &digest);
	if (ret != 0) {
		return ret;
	}
	return pqcp_deployment_evidence_digest_final_hex(&digest, output);
}

static void emit_profile(
	const struct pqcp_adaptive_profile *profile,
	uint32_t index)
{
	char digest[PQCP_ADAPTIVE_DIGEST_HEX_CHARS + 1U];

	if (profile_digest_hex(profile, digest) != 0) {
		pqcp_adaptive_internal_set_text(
			digest, sizeof(digest), "invalid");
	}
	printk("PQCP_ADAPTIVE_PROFILE schema=%u index=%u id=%s kind=%s operations=0x%08x security=%u mlkem=%u mldsa=%u latency_us=%llu cycles=%llu ram=%llu stack=%llu heap=%llu flash=%llu energy_uj=%llu evidence=0x%08x priority=%u enabled=%u native=%u production=%u hardware=%u hybrid=%u digest=%s\n",
	       profile->schema_version,
	       index,
	       profile->profile_id,
	       profile_kind_str(profile->kind),
	       profile->operation_mask,
	       profile->security_level,
	       profile->mlkem_level,
	       profile->mldsa_level,
	       (unsigned long long)profile->nominal_latency_us,
	       (unsigned long long)profile->nominal_cycles,
	       (unsigned long long)profile->ram_bytes,
	       (unsigned long long)profile->stack_bytes,
	       (unsigned long long)profile->heap_bytes,
	       (unsigned long long)profile->flash_bytes,
	       (unsigned long long)profile->energy_uj,
	       profile->evidence_mask,
	       profile->priority,
	       profile->enabled ? 1U : 0U,
	       profile->native_provider ? 1U : 0U,
	       profile->production_allowed ? 1U : 0U,
	       profile->hardware_validated ? 1U : 0U,
	       profile->hybrid_required ? 1U : 0U,
	       digest);
}

int pqcp_adaptive_profile_registry_emit(
	const struct pqcp_adaptive_profile_registry *registry)
{
	int ret;

	ret = pqcp_adaptive_profile_registry_validate(registry);
	if (ret != 0) {
		return ret;
	}
	for (uint32_t index = 0U; index < registry->count; ++index) {
		emit_profile(&registry->profiles[index], index);
	}
	printk("PQCP_ADAPTIVE_PROFILE_REGISTRY schema=%u count=%u enabled=%u native=%u production=%u digest=%s\n",
	       registry->schema_version,
	       registry->count,
	       registry->enabled_count,
	       registry->native_count,
	       registry->production_count,
	       registry->registry_digest_hex);
	return 0;
}
