/*
 * SPDX-License-Identifier: MIT
 *
 * Bounded on-device calibration of operational PQC profile estimates.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/printk.h>

#include <pqcp_zephyr/adaptive_control.h>

#include "adaptive_internal.h"

#define PQCP_ADAPTIVE_CALIBRATION_DOMAIN UINT64_C(0x41445043414c4942)
#define PQCP_ADAPTIVE_CALIBRATION_ALPHA_NUMERATOR 1U
#define PQCP_ADAPTIVE_CALIBRATION_ALPHA_DENOMINATOR 8U
#define PQCP_ADAPTIVE_CALIBRATION_MAX_DRIFT_PERMILLE 400U

static bool observation_valid(
	const struct pqcp_adaptive_calibration_observation *observation)
{
	return observation != NULL &&
	       observation->timestamp_ms != 0U &&
	       observation->latency_us != 0U &&
	       observation->cycles != 0U &&
	       observation->ram_bytes != 0U &&
	       observation->stack_bytes != 0U &&
	       observation->energy_uj != 0U &&
	       pqcp_adaptive_internal_id_valid(observation->profile_id);
}

static int calibration_index(
	const struct pqcp_adaptive_calibration_table *table,
	const char *profile_id)
{
	for (uint32_t index = 0U; index < table->count; ++index) {
		if (strcmp(table->profiles[index].profile_id,
			   profile_id) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static uint64_t ewma(uint64_t current, uint64_t observation)
{
	uint64_t retained;
	uint64_t added;

	if (current == 0U) {
		return observation;
	}
	retained = pqcp_adaptive_internal_saturating_mul_u64(
		current,
		PQCP_ADAPTIVE_CALIBRATION_ALPHA_DENOMINATOR -
		PQCP_ADAPTIVE_CALIBRATION_ALPHA_NUMERATOR);
	added = pqcp_adaptive_internal_saturating_mul_u64(
		observation,
		PQCP_ADAPTIVE_CALIBRATION_ALPHA_NUMERATOR);
	return pqcp_adaptive_internal_saturating_add_u64(
		retained, added) /
		PQCP_ADAPTIVE_CALIBRATION_ALPHA_DENOMINATOR;
}

static bool within_drift(uint64_t baseline, uint64_t value)
{
	uint64_t difference;
	uint32_t drift;

	if (baseline == 0U) {
		return true;
	}
	difference = baseline > value ?
		baseline - value : value - baseline;
	drift = pqcp_adaptive_internal_permille(
		difference, baseline);
	return drift <= PQCP_ADAPTIVE_CALIBRATION_MAX_DRIFT_PERMILLE;
}

static uint32_t calibration_confidence(
	const struct pqcp_adaptive_profile_calibration *calibration)
{
	uint32_t sample_score;
	uint32_t rejection_penalty;
	uint32_t range_penalty = 0U;

	sample_score = calibration->accepted_count >= 32U ?
		800U : calibration->accepted_count * 25U;
	if (calibration->sample_count == 0U) {
		return 0U;
	}
	rejection_penalty =
		(calibration->rejected_count * 300U) /
		calibration->sample_count;
	if (calibration->latency_min_us != 0U &&
	    calibration->latency_max_us >
		    calibration->latency_min_us) {
		range_penalty =
			pqcp_adaptive_internal_permille(
				calibration->latency_max_us -
					calibration->latency_min_us,
				calibration->latency_min_us) / 4U;
	}
	if (range_penalty > 200U) {
		range_penalty = 200U;
	}
	if (sample_score <= rejection_penalty + range_penalty) {
		return 0U;
	}
	return pqcp_adaptive_internal_clamp_u32(
		200U + sample_score -
		rejection_penalty - range_penalty,
		0U, PQCP_ADAPTIVE_SCORE_MAX);
}

static int profile_calibration_digest(
	struct pqcp_adaptive_profile_calibration *calibration)
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_CALIBRATION_DOMAIN);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, calibration->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, calibration->sample_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, calibration->accepted_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, calibration->rejected_count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, calibration->confidence);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, calibration->last_timestamp_ms);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, calibration->latency_ewma_us);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, calibration->cycles_ewma);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, calibration->ram_high_watermark);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, calibration->stack_high_watermark);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, calibration->heap_high_watermark);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, calibration->energy_ewma_uj);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, calibration->latency_min_us);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, calibration->latency_max_us);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, calibration->energy_min_uj);
	pqcp_deployment_evidence_digest_update_u64(
		&digest, calibration->energy_max_uj);
	pqcp_deployment_evidence_digest_update_text(
		&digest, calibration->profile_id);
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, calibration->calibration_digest_hex);
}

static int table_digest(
	struct pqcp_adaptive_calibration_table *table)
{
	struct pqcp_deployment_evidence_digest digest;

	pqcp_deployment_evidence_digest_init(
		&digest, PQCP_ADAPTIVE_CALIBRATION_DOMAIN ^ UINT64_C(0x54));
	pqcp_deployment_evidence_digest_update_u32(
		&digest, table->schema_version);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, table->count);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, table->accepted_observations);
	pqcp_deployment_evidence_digest_update_u32(
		&digest, table->rejected_observations);
	for (uint32_t index = 0U; index < table->count; ++index) {
		pqcp_deployment_evidence_digest_update_text(
			&digest,
			table->profiles[index].profile_id);
		pqcp_deployment_evidence_digest_update_text(
			&digest,
			table->profiles[index]
				.calibration_digest_hex);
	}
	return pqcp_deployment_evidence_digest_final_hex(
		&digest, table->table_digest_hex);
}

static void initialize_calibration(
	struct pqcp_adaptive_profile_calibration *calibration,
	const char *profile_id)
{
	memset(calibration, 0, sizeof(*calibration));
	calibration->schema_version =
		PQCP_ADAPTIVE_SCHEMA_VERSION;
	pqcp_adaptive_internal_set_text(
		calibration->profile_id,
		sizeof(calibration->profile_id), profile_id);
}

static bool observation_acceptable(
	const struct pqcp_adaptive_profile *profile,
	const struct pqcp_adaptive_profile_calibration *calibration,
	const struct pqcp_adaptive_calibration_observation *observation)
{
	uint64_t latency_baseline =
		calibration->latency_ewma_us != 0U ?
		calibration->latency_ewma_us :
		profile->nominal_latency_us;
	uint64_t cycles_baseline =
		calibration->cycles_ewma != 0U ?
		calibration->cycles_ewma :
		profile->nominal_cycles;
	uint64_t energy_baseline =
		calibration->energy_ewma_uj != 0U ?
		calibration->energy_ewma_uj :
		profile->energy_uj;

	if (!observation->successful ||
	    !within_drift(
		    latency_baseline, observation->latency_us) ||
	    (cycles_baseline != 0U &&
	     !within_drift(cycles_baseline, observation->cycles)) ||
	    (energy_baseline != 0U &&
	     !within_drift(energy_baseline, observation->energy_uj))) {
		return false;
	}
	if (observation->ram_bytes >
		    profile->ram_bytes * 2U ||
	    observation->stack_bytes >
		    profile->stack_bytes * 2U ||
	    (profile->heap_bytes != 0U &&
	     observation->heap_bytes >
		     profile->heap_bytes * 2U)) {
		return false;
	}
	return true;
}

static void accept_observation(
	struct pqcp_adaptive_profile_calibration *calibration,
	const struct pqcp_adaptive_calibration_observation *observation)
{
	calibration->accepted_count++;
	calibration->latency_ewma_us = ewma(
		calibration->latency_ewma_us,
		observation->latency_us);
	calibration->cycles_ewma = ewma(
		calibration->cycles_ewma, observation->cycles);
	calibration->energy_ewma_uj = ewma(
		calibration->energy_ewma_uj,
		observation->energy_uj);
	if (observation->ram_bytes >
	    calibration->ram_high_watermark) {
		calibration->ram_high_watermark =
			observation->ram_bytes;
	}
	if (observation->stack_bytes >
	    calibration->stack_high_watermark) {
		calibration->stack_high_watermark =
			observation->stack_bytes;
	}
	if (observation->heap_bytes >
	    calibration->heap_high_watermark) {
		calibration->heap_high_watermark =
			observation->heap_bytes;
	}
	if (calibration->latency_min_us == 0U ||
	    observation->latency_us <
		    calibration->latency_min_us) {
		calibration->latency_min_us =
			observation->latency_us;
	}
	if (observation->latency_us >
	    calibration->latency_max_us) {
		calibration->latency_max_us =
			observation->latency_us;
	}
	if (calibration->energy_min_uj == 0U ||
	    observation->energy_uj <
		    calibration->energy_min_uj) {
		calibration->energy_min_uj =
			observation->energy_uj;
	}
	if (observation->energy_uj >
	    calibration->energy_max_uj) {
		calibration->energy_max_uj =
			observation->energy_uj;
	}
}

int pqcp_adaptive_calibration_init(
	struct pqcp_adaptive_calibration_table *table)
{
	if (table == NULL) {
		return -EINVAL;
	}
	memset(table, 0, sizeof(*table));
	table->schema_version = PQCP_ADAPTIVE_SCHEMA_VERSION;
	return table_digest(table);
}

int pqcp_adaptive_calibration_observe(
	struct pqcp_adaptive_calibration_table *table,
	const struct pqcp_adaptive_profile_registry *registry,
	const struct pqcp_adaptive_calibration_observation *observation)
{
	const struct pqcp_adaptive_profile *profile;
	struct pqcp_adaptive_profile_calibration *calibration;
	int index;

	if (table == NULL ||
	    table->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    pqcp_adaptive_profile_registry_validate(registry) != 0 ||
	    !observation_valid(observation)) {
		return -EINVAL;
	}
	profile = pqcp_adaptive_profile_registry_find(
		registry, observation->profile_id);
	if (profile == NULL) {
		table->rejected_observations++;
		return -ENOENT;
	}
	index = calibration_index(table, observation->profile_id);
	if (index < 0) {
		if (table->count >= PQCP_ADAPTIVE_MAX_PROFILES) {
			table->rejected_observations++;
			return -ENOSPC;
		}
		index = (int)table->count++;
		initialize_calibration(
			&table->profiles[index],
			observation->profile_id);
	}
	calibration = &table->profiles[index];
	if (calibration->last_timestamp_ms != 0U &&
	    observation->timestamp_ms <=
		    calibration->last_timestamp_ms) {
		calibration->sample_count++;
		calibration->rejected_count++;
		table->rejected_observations++;
		calibration->confidence =
			calibration_confidence(calibration);
		(void)profile_calibration_digest(calibration);
		(void)table_digest(table);
		return -ERANGE;
	}
	calibration->sample_count++;
	calibration->last_timestamp_ms =
		observation->timestamp_ms;
	if (observation_acceptable(
		    profile, calibration, observation)) {
		accept_observation(calibration, observation);
		table->accepted_observations++;
	} else {
		calibration->rejected_count++;
		table->rejected_observations++;
	}
	calibration->confidence =
		calibration_confidence(calibration);
	if (profile_calibration_digest(calibration) != 0) {
		return -EBADMSG;
	}
	if (table_digest(table) != 0) {
		return -EBADMSG;
	}
	return observation->successful &&
	       observation_acceptable(
		       profile, calibration, observation) ?
		0 : -EAGAIN;
}

int pqcp_adaptive_calibration_reset_profile(
	struct pqcp_adaptive_calibration_table *table,
	const char *profile_id)
{
	int index;

	if (table == NULL ||
	    table->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_id_valid(profile_id)) {
		return -EINVAL;
	}
	index = calibration_index(table, profile_id);
	if (index < 0) {
		return -ENOENT;
	}
	if (table->accepted_observations >=
	    table->profiles[index].accepted_count) {
		table->accepted_observations -=
			table->profiles[index].accepted_count;
	} else {
		table->accepted_observations = 0U;
	}
	if (table->rejected_observations >=
	    table->profiles[index].rejected_count) {
		table->rejected_observations -=
			table->profiles[index].rejected_count;
	} else {
		table->rejected_observations = 0U;
	}
	for (uint32_t current = (uint32_t)index;
	     current + 1U < table->count; ++current) {
		table->profiles[current] =
			table->profiles[current + 1U];
	}
	if (table->count != 0U) {
		memset(&table->profiles[table->count - 1U], 0,
		       sizeof(table->profiles[0]));
		table->count--;
	}
	return table_digest(table);
}

int pqcp_adaptive_calibration_apply(
	const struct pqcp_adaptive_calibration_table *table,
	const struct pqcp_adaptive_profile *profile,
	uint32_t minimum_confidence,
	struct pqcp_adaptive_profile *calibrated_profile)
{
	const struct pqcp_adaptive_profile_calibration *calibration;
	int index;

	if (table == NULL ||
	    table->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_profile_valid(profile) ||
	    minimum_confidence > PQCP_ADAPTIVE_SCORE_MAX ||
	    calibrated_profile == NULL) {
		return -EINVAL;
	}
	index = calibration_index(table, profile->profile_id);
	if (index < 0) {
		return -ENOENT;
	}
	calibration = &table->profiles[index];
	if (calibration->confidence < minimum_confidence ||
	    calibration->accepted_count < 4U) {
		return -EAGAIN;
	}
	*calibrated_profile = *profile;
	calibrated_profile->nominal_latency_us =
		calibration->latency_ewma_us;
	calibrated_profile->nominal_cycles =
		calibration->cycles_ewma;
	calibrated_profile->energy_uj =
		calibration->energy_ewma_uj;
	calibrated_profile->latency_source =
		PQCP_ADAPTIVE_METRIC_CALIBRATED;
	calibrated_profile->cycles_source =
		PQCP_ADAPTIVE_METRIC_CALIBRATED;
	calibrated_profile->memory_source =
		PQCP_ADAPTIVE_METRIC_CALIBRATED;
	calibrated_profile->energy_source =
		PQCP_ADAPTIVE_METRIC_CALIBRATED;
	calibrated_profile->observation_count =
		calibration->accepted_count;
	if (calibration->ram_high_watermark >
	    calibrated_profile->ram_bytes) {
		calibrated_profile->ram_bytes =
			calibration->ram_high_watermark;
	}
	if (calibration->stack_high_watermark >
	    calibrated_profile->stack_bytes) {
		calibrated_profile->stack_bytes =
			calibration->stack_high_watermark;
	}
	if (calibration->heap_high_watermark >
	    calibrated_profile->heap_bytes) {
		calibrated_profile->heap_bytes =
			calibration->heap_high_watermark;
	}
	return pqcp_adaptive_internal_profile_valid(
		calibrated_profile) ? 0 : -EBADMSG;
}

static int validate_profile_calibration(
	const struct pqcp_adaptive_profile_calibration *calibration,
	const struct pqcp_adaptive_profile_registry *registry)
{
	struct pqcp_adaptive_profile_calibration copy;

	if (calibration == NULL ||
	    calibration->schema_version !=
		    PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    !pqcp_adaptive_internal_id_valid(
		    calibration->profile_id) ||
	    calibration->accepted_count +
		    calibration->rejected_count !=
		    calibration->sample_count ||
	    calibration->confidence >
		    PQCP_ADAPTIVE_SCORE_MAX ||
	    calibration->accepted_count >
		    calibration->sample_count ||
	    (calibration->accepted_count != 0U &&
	     (calibration->latency_ewma_us == 0U ||
	      calibration->cycles_ewma == 0U ||
	      calibration->energy_ewma_uj == 0U ||
	      calibration->ram_high_watermark == 0U ||
	      calibration->stack_high_watermark == 0U)) ||
	    (calibration->latency_min_us != 0U &&
	     calibration->latency_min_us >
		     calibration->latency_max_us) ||
	    (calibration->energy_min_uj != 0U &&
	     calibration->energy_min_uj >
		     calibration->energy_max_uj) ||
	    pqcp_adaptive_profile_registry_find(
		    registry, calibration->profile_id) == NULL) {
		return -EBADMSG;
	}
	copy = *calibration;
	if (calibration_confidence(&copy) !=
	    calibration->confidence) {
		return -EBADMSG;
	}
	if (profile_calibration_digest(&copy) != 0 ||
	    strcmp(copy.calibration_digest_hex,
		   calibration->calibration_digest_hex) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_adaptive_calibration_validate(
	const struct pqcp_adaptive_calibration_table *table,
	const struct pqcp_adaptive_profile_registry *registry)
{
	struct pqcp_adaptive_calibration_table copy;
	uint32_t accepted = 0U;
	uint32_t rejected = 0U;

	if (table == NULL ||
	    table->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    table->count > PQCP_ADAPTIVE_MAX_PROFILES ||
	    pqcp_adaptive_profile_registry_validate(registry) != 0) {
		return -EINVAL;
	}
	for (uint32_t index = 0U; index < table->count; ++index) {
		if (validate_profile_calibration(
			    &table->profiles[index], registry) != 0) {
			return -EBADMSG;
		}
		if (index != 0U &&
		    strcmp(table->profiles[index - 1U].profile_id,
			   table->profiles[index].profile_id) >= 0) {
			return -EBADMSG;
		}
		accepted += table->profiles[index].accepted_count;
		rejected += table->profiles[index].rejected_count;
	}
	if (accepted != table->accepted_observations ||
	    rejected != table->rejected_observations) {
		return -EBADMSG;
	}
	copy = *table;
	if (table_digest(&copy) != 0 ||
	    strcmp(copy.table_digest_hex,
		   table->table_digest_hex) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int pqcp_adaptive_calibration_emit(
	const struct pqcp_adaptive_calibration_table *table)
{
	if (table == NULL ||
	    table->schema_version != PQCP_ADAPTIVE_SCHEMA_VERSION ||
	    table->count > PQCP_ADAPTIVE_MAX_PROFILES) {
		return -EINVAL;
	}
	for (uint32_t index = 0U; index < table->count; ++index) {
		const struct pqcp_adaptive_profile_calibration *calibration =
			&table->profiles[index];

		printk("PQCP_ADAPTIVE_CALIBRATION schema=%u index=%u profile=%s samples=%u accepted=%u rejected=%u confidence=%u last_ms=%llu latency_ewma_us=%llu latency_min_us=%llu latency_max_us=%llu cycles_ewma=%llu ram_high=%llu stack_high=%llu heap_high=%llu energy_ewma_uj=%llu energy_min_uj=%llu energy_max_uj=%llu digest=%s\n",
		       calibration->schema_version,
		       index,
		       calibration->profile_id,
		       calibration->sample_count,
		       calibration->accepted_count,
		       calibration->rejected_count,
		       calibration->confidence,
		       (unsigned long long)calibration->last_timestamp_ms,
		       (unsigned long long)calibration->latency_ewma_us,
		       (unsigned long long)calibration->latency_min_us,
		       (unsigned long long)calibration->latency_max_us,
		       (unsigned long long)calibration->cycles_ewma,
		       (unsigned long long)calibration->ram_high_watermark,
		       (unsigned long long)calibration->stack_high_watermark,
		       (unsigned long long)calibration->heap_high_watermark,
		       (unsigned long long)calibration->energy_ewma_uj,
		       (unsigned long long)calibration->energy_min_uj,
		       (unsigned long long)calibration->energy_max_uj,
		       calibration->calibration_digest_hex);
	}
	printk("PQCP_ADAPTIVE_CALIBRATION_TABLE schema=%u profiles=%u accepted=%u rejected=%u digest=%s\n",
	       table->schema_version,
	       table->count,
	       table->accepted_observations,
	       table->rejected_observations,
	       table->table_digest_hex);
	return 0;
}
