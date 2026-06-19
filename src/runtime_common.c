/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Common primitives for the allocation-free PQCP execution runtime.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/clock.h>

#include <pqcp_zephyr/runtime.h>

#include "runtime_internal.h"

#define PQCP_RUNTIME_USAGE_KNOWN_MASK \
	(PQCP_RUNTIME_USAGE_ENCAPSULATE | \
	 PQCP_RUNTIME_USAGE_DECAPSULATE | \
	 PQCP_RUNTIME_USAGE_SIGN | \
	 PQCP_RUNTIME_USAGE_VERIFY | \
	 PQCP_RUNTIME_USAGE_DERIVE | \
	 PQCP_RUNTIME_USAGE_EXPORT_PUBLIC | \
	 PQCP_RUNTIME_USAGE_DESTROY)

static bool text_character_allowed(char value)
{
	return (value >= 'a' && value <= 'z') ||
	       (value >= 'A' && value <= 'Z') ||
	       (value >= '0' && value <= '9') ||
	       value == '-' || value == '_' || value == '.' ||
	       value == ':' || value == '/';
}

int pqcp_runtime_internal_copy_text(
	char *destination,
	size_t capacity,
	const char *source)
{
	size_t length;

	if (destination == NULL || capacity == 0U || source == NULL) {
		return -EINVAL;
	}
	length = strnlen(source, capacity);
	if (length == 0U || length >= capacity) {
		destination[0] = '\0';
		return -ENAMETOOLONG;
	}
	memcpy(destination, source, length);
	destination[length] = '\0';
	return 0;
}

bool pqcp_runtime_internal_text_valid(
	const char *text,
	size_t capacity)
{
	size_t length;

	if (text == NULL || capacity < 2U) {
		return false;
	}
	length = strnlen(text, capacity);
	if (length == 0U || length >= capacity) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		if (!text_character_allowed(text[index])) {
			return false;
		}
	}
	return true;
}

bool pqcp_runtime_internal_owner_valid(const char *owner)
{
	return pqcp_runtime_internal_text_valid(
		owner, PQCP_RUNTIME_OWNER_MAX_CHARS);
}

bool pqcp_runtime_internal_label_valid(const char *label)
{
	return pqcp_runtime_internal_text_valid(
		label, PQCP_RUNTIME_LABEL_MAX_CHARS);
}

bool pqcp_runtime_internal_key_family_valid(
	enum pqcp_runtime_key_family family)
{
	return family >= PQCP_RUNTIME_KEY_MLKEM_PUBLIC &&
	       family <= PQCP_RUNTIME_KEY_AEAD;
}

bool pqcp_runtime_internal_key_backend_valid(
	enum pqcp_runtime_key_backend backend)
{
	return backend == PQCP_RUNTIME_KEY_BACKEND_VOLATILE ||
	       backend == PQCP_RUNTIME_KEY_BACKEND_PSA_PERSISTENT;
}

bool pqcp_runtime_internal_job_type_valid(
	enum pqcp_runtime_job_type type)
{
	return type >= PQCP_RUNTIME_JOB_MLKEM_KEYGEN &&
	       type <= PQCP_RUNTIME_JOB_MLDSA_VERIFY;
}

bool pqcp_runtime_internal_priority_valid(
	enum pqcp_runtime_job_priority priority)
{
	return priority >= PQCP_RUNTIME_PRIORITY_BACKGROUND &&
	       priority <= PQCP_RUNTIME_PRIORITY_CRITICAL;
}

bool pqcp_runtime_internal_usage_valid(uint32_t usage)
{
	return usage != 0U &&
	       (usage & ~PQCP_RUNTIME_USAGE_KNOWN_MASK) == 0U;
}

static bool mlkem_level_valid(uint32_t level)
{
	return level == PQCP_MLKEM_512 ||
	       level == PQCP_MLKEM_768 ||
	       level == PQCP_MLKEM_1024;
}

static bool mldsa_level_valid(uint32_t level)
{
	return level == PQCP_MLDSA_44 ||
	       level == PQCP_MLDSA_65 ||
	       level == PQCP_MLDSA_87;
}

bool pqcp_runtime_internal_level_valid(
	enum pqcp_runtime_key_family family,
	uint32_t level)
{
	switch (family) {
	case PQCP_RUNTIME_KEY_MLKEM_PUBLIC:
	case PQCP_RUNTIME_KEY_MLKEM_KEYPAIR:
		return mlkem_level_valid(level);
	case PQCP_RUNTIME_KEY_MLDSA_PUBLIC:
	case PQCP_RUNTIME_KEY_MLDSA_KEYPAIR:
		return mldsa_level_valid(level);
	case PQCP_RUNTIME_KEY_SHARED_SECRET:
	case PQCP_RUNTIME_KEY_AEAD:
		return level == 0U || level == 256U;
	default:
		return false;
	}
}

size_t pqcp_runtime_internal_public_size(
	enum pqcp_runtime_key_family family,
	uint32_t level)
{
	switch (family) {
	case PQCP_RUNTIME_KEY_MLKEM_PUBLIC:
	case PQCP_RUNTIME_KEY_MLKEM_KEYPAIR:
		return pqcp_mlkem_pk_size((pqcp_mlkem_level_t)level);
	case PQCP_RUNTIME_KEY_MLDSA_PUBLIC:
	case PQCP_RUNTIME_KEY_MLDSA_KEYPAIR:
		return pqcp_mldsa_pk_size((pqcp_mldsa_level_t)level);
	case PQCP_RUNTIME_KEY_SHARED_SECRET:
	case PQCP_RUNTIME_KEY_AEAD:
	default:
		return 0U;
	}
}

size_t pqcp_runtime_internal_secret_size(
	enum pqcp_runtime_key_family family,
	uint32_t level)
{
	switch (family) {
	case PQCP_RUNTIME_KEY_MLKEM_KEYPAIR:
		return pqcp_mlkem_sk_size((pqcp_mlkem_level_t)level);
	case PQCP_RUNTIME_KEY_MLDSA_KEYPAIR:
		return pqcp_mldsa_sk_size((pqcp_mldsa_level_t)level);
	case PQCP_RUNTIME_KEY_SHARED_SECRET:
		return PQCP_MLKEM_SS_SIZE;
	case PQCP_RUNTIME_KEY_AEAD:
		return PQCP_RUNTIME_AEAD_KEY_BYTES;
	case PQCP_RUNTIME_KEY_MLKEM_PUBLIC:
	case PQCP_RUNTIME_KEY_MLDSA_PUBLIC:
	default:
		return 0U;
	}
}

uint32_t pqcp_runtime_internal_security_level(
	uint32_t mlkem_level,
	uint32_t mldsa_level)
{
	uint32_t kem_security = 0U;
	uint32_t sig_security = 0U;

	switch (mlkem_level) {
	case PQCP_MLKEM_512:
		kem_security = 1U;
		break;
	case PQCP_MLKEM_768:
		kem_security = 3U;
		break;
	case PQCP_MLKEM_1024:
		kem_security = 5U;
		break;
	default:
		break;
	}
	switch (mldsa_level) {
	case PQCP_MLDSA_44:
		sig_security = 2U;
		break;
	case PQCP_MLDSA_65:
		sig_security = 3U;
		break;
	case PQCP_MLDSA_87:
		sig_security = 5U;
		break;
	default:
		break;
	}
	if (kem_security == 0U) {
		return sig_security;
	}
	if (sig_security == 0U) {
		return kem_security;
	}
	return kem_security < sig_security ?
		kem_security : sig_security;
}

uint64_t pqcp_runtime_internal_now_ms(void)
{
	return (uint64_t)k_uptime_get();
}

uint64_t pqcp_runtime_internal_cycles(void)
{
	return k_cycle_get_64();
}

uint64_t pqcp_runtime_internal_cycles_to_us(uint64_t cycles)
{
	return k_cyc_to_us_floor64(cycles);
}

int pqcp_runtime_internal_sha256(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_RUNTIME_DIGEST_BYTES])
{
	size_t output_length = 0U;
	psa_status_t status;

	if ((input == NULL && input_length != 0U) || output == NULL) {
		return -EINVAL;
	}
	status = psa_hash_compute(
		PSA_ALG_SHA_256, input, input_length,
		output, PQCP_RUNTIME_DIGEST_BYTES, &output_length);
	if (status != PSA_SUCCESS) {
		pqcp_runtime_secure_zero(
			output, PQCP_RUNTIME_DIGEST_BYTES);
		return -EIO;
	}
	return output_length == PQCP_RUNTIME_DIGEST_BYTES ?
		0 : -EBADMSG;
}

int pqcp_runtime_internal_sha256_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_RUNTIME_DIGEST_BYTES])
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	size_t output_length = 0U;
	psa_status_t status;

	if (parts == NULL || lengths == NULL ||
	    part_count == 0U || output == NULL) {
		return -EINVAL;
	}
	status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}
	for (size_t index = 0U; index < part_count; ++index) {
		if (parts[index] == NULL && lengths[index] != 0U) {
			(void)psa_hash_abort(&operation);
			return -EINVAL;
		}
		status = psa_hash_update(
			&operation, parts[index], lengths[index]);
		if (status != PSA_SUCCESS) {
			(void)psa_hash_abort(&operation);
			return -EIO;
		}
	}
	status = psa_hash_finish(
		&operation, output, PQCP_RUNTIME_DIGEST_BYTES,
		&output_length);
	if (status != PSA_SUCCESS ||
	    output_length != PQCP_RUNTIME_DIGEST_BYTES) {
		(void)psa_hash_abort(&operation);
		pqcp_runtime_secure_zero(
			output, PQCP_RUNTIME_DIGEST_BYTES);
		return -EIO;
	}
	return 0;
}

int pqcp_runtime_internal_hex(
	const uint8_t *input,
	size_t input_length,
	char *output,
	size_t output_capacity)
{
	static const char hex[] = "0123456789abcdef";

	if ((input == NULL && input_length != 0U) ||
	    output == NULL ||
	    output_capacity < input_length * 2U + 1U) {
		return -EINVAL;
	}
	for (size_t index = 0U; index < input_length; ++index) {
		output[index * 2U] = hex[input[index] >> 4U];
		output[index * 2U + 1U] = hex[input[index] & 0x0fU];
	}
	output[input_length * 2U] = '\0';
	return 0;
}

int pqcp_runtime_internal_hmac_sha256(
	const uint8_t *key,
	size_t key_length,
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_RUNTIME_DIGEST_BYTES])
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = 0U;
	size_t mac_length = 0U;
	psa_status_t status;
	int result = 0;

	if (key == NULL || key_length == 0U ||
	    (input == NULL && input_length != 0U) ||
	    output == NULL) {
		return -EINVAL;
	}
	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, key_length * 8U);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	status = psa_import_key(
		&attributes, key, key_length, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}
	status = psa_mac_compute(
		key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
		input, input_length, output,
		PQCP_RUNTIME_DIGEST_BYTES, &mac_length);
	if (status != PSA_SUCCESS ||
	    mac_length != PQCP_RUNTIME_DIGEST_BYTES) {
		result = -EIO;
		pqcp_runtime_secure_zero(
			output, PQCP_RUNTIME_DIGEST_BYTES);
	}
	(void)psa_destroy_key(key_id);
	return result;
}

int pqcp_runtime_internal_hkdf_sha256(
	const uint8_t *salt,
	size_t salt_length,
	const uint8_t *input_key,
	size_t input_key_length,
	const uint8_t *info,
	size_t info_length,
	uint8_t *output,
	size_t output_length)
{
	psa_key_derivation_operation_t operation =
		PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_status_t status;

	if (input_key == NULL || input_key_length == 0U ||
	    output == NULL || output_length == 0U ||
	    (salt == NULL && salt_length != 0U) ||
	    (info == NULL && info_length != 0U)) {
		return -EINVAL;
	}
	status = psa_key_derivation_setup(
		&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_bytes(
			&operation, PSA_KEY_DERIVATION_INPUT_SALT,
			salt, salt_length);
	}
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_bytes(
			&operation, PSA_KEY_DERIVATION_INPUT_SECRET,
			input_key, input_key_length);
	}
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_bytes(
			&operation, PSA_KEY_DERIVATION_INPUT_INFO,
			info, info_length);
	}
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_output_bytes(
			&operation, output, output_length);
	}
	(void)psa_key_derivation_abort(&operation);
	if (status != PSA_SUCCESS) {
		pqcp_runtime_secure_zero(output, output_length);
		return -EIO;
	}
	return 0;
}

void pqcp_runtime_internal_write_u16(uint8_t *output, uint16_t value)
{
	output[0] = (uint8_t)(value >> 8U);
	output[1] = (uint8_t)value;
}

void pqcp_runtime_internal_write_u32(uint8_t *output, uint32_t value)
{
	output[0] = (uint8_t)(value >> 24U);
	output[1] = (uint8_t)(value >> 16U);
	output[2] = (uint8_t)(value >> 8U);
	output[3] = (uint8_t)value;
}

void pqcp_runtime_internal_write_u64(uint8_t *output, uint64_t value)
{
	for (size_t index = 0U; index < 8U; ++index) {
		output[index] =
			(uint8_t)(value >> ((7U - index) * 8U));
	}
}

uint16_t pqcp_runtime_internal_read_u16(const uint8_t *input)
{
	return ((uint16_t)input[0] << 8U) |
	       (uint16_t)input[1];
}

uint32_t pqcp_runtime_internal_read_u32(const uint8_t *input)
{
	return ((uint32_t)input[0] << 24U) |
	       ((uint32_t)input[1] << 16U) |
	       ((uint32_t)input[2] << 8U) |
	       (uint32_t)input[3];
}

uint64_t pqcp_runtime_internal_read_u64(const uint8_t *input)
{
	uint64_t value = 0U;

	for (size_t index = 0U; index < 8U; ++index) {
		value = (value << 8U) | input[index];
	}
	return value;
}

int pqcp_runtime_internal_profile_id(
	enum pqcp_runtime_key_family family,
	uint32_t mlkem_level,
	uint32_t mldsa_level,
	char output[PQCP_RUNTIME_PROFILE_MAX_CHARS])
{
	int written;

	if (output == NULL) {
		return -EINVAL;
	}
	switch (family) {
	case PQCP_RUNTIME_KEY_MLKEM_PUBLIC:
	case PQCP_RUNTIME_KEY_MLKEM_KEYPAIR:
		written = snprintf(
			output, PQCP_RUNTIME_PROFILE_MAX_CHARS,
			"mlkem%u-runtime", mlkem_level);
		break;
	case PQCP_RUNTIME_KEY_MLDSA_PUBLIC:
	case PQCP_RUNTIME_KEY_MLDSA_KEYPAIR:
		written = snprintf(
			output, PQCP_RUNTIME_PROFILE_MAX_CHARS,
			"mldsa%u-runtime", mldsa_level);
		break;
	default:
		written = snprintf(
			output, PQCP_RUNTIME_PROFILE_MAX_CHARS,
			"hybrid%u-%u-runtime",
			mlkem_level, mldsa_level);
		break;
	}
	return written > 0 &&
	       written < PQCP_RUNTIME_PROFILE_MAX_CHARS ?
		0 : -ENOSPC;
}

const char *pqcp_runtime_status_str(enum pqcp_runtime_status status)
{
	switch (status) {
	case PQCP_RUNTIME_STATUS_IDLE:
		return "IDLE";
	case PQCP_RUNTIME_STATUS_QUEUED:
		return "QUEUED";
	case PQCP_RUNTIME_STATUS_RUNNING:
		return "RUNNING";
	case PQCP_RUNTIME_STATUS_COMPLETED:
		return "COMPLETED";
	case PQCP_RUNTIME_STATUS_CANCELLED:
		return "CANCELLED";
	case PQCP_RUNTIME_STATUS_EXPIRED:
		return "EXPIRED";
	case PQCP_RUNTIME_STATUS_FAILED:
		return "FAILED";
	default:
		return "UNKNOWN";
	}
}

const char *pqcp_runtime_metric_source_str(
	enum pqcp_runtime_metric_source source)
{
	switch (source) {
	case PQCP_RUNTIME_METRIC_UNKNOWN:
		return "unknown";
	case PQCP_RUNTIME_METRIC_BOOTSTRAP_PRIOR:
		return "bootstrap_prior";
	case PQCP_RUNTIME_METRIC_MEASURED:
		return "measured";
	case PQCP_RUNTIME_METRIC_CALIBRATED:
		return "calibrated";
	default:
		return "invalid";
	}
}

const char *pqcp_runtime_job_type_str(enum pqcp_runtime_job_type type)
{
	switch (type) {
	case PQCP_RUNTIME_JOB_MLKEM_KEYGEN:
		return "mlkem_keygen";
	case PQCP_RUNTIME_JOB_MLKEM_ENCAPSULATE:
		return "mlkem_encapsulate";
	case PQCP_RUNTIME_JOB_MLKEM_DECAPSULATE:
		return "mlkem_decapsulate";
	case PQCP_RUNTIME_JOB_MLDSA_KEYGEN:
		return "mldsa_keygen";
	case PQCP_RUNTIME_JOB_MLDSA_SIGN:
		return "mldsa_sign";
	case PQCP_RUNTIME_JOB_MLDSA_VERIFY:
		return "mldsa_verify";
	default:
		return "unknown";
	}
}

void pqcp_runtime_secure_zero(void *buffer, size_t length)
{
	volatile uint8_t *bytes = buffer;

	if (buffer == NULL) {
		return;
	}
	while (length-- != 0U) {
		*bytes++ = 0U;
	}
}

bool pqcp_runtime_key_handle_is_valid(
	const struct pqcp_runtime_key_handle *handle)
{
	return handle != NULL &&
	       handle->generation != 0U &&
	       pqcp_runtime_internal_key_backend_valid(handle->backend) &&
	       pqcp_runtime_internal_key_family_valid(handle->family) &&
	       pqcp_runtime_internal_level_valid(
		       handle->family, handle->level);
}

bool pqcp_runtime_key_handle_equal(
	const struct pqcp_runtime_key_handle *left,
	const struct pqcp_runtime_key_handle *right)
{
	return pqcp_runtime_key_handle_is_valid(left) &&
	       pqcp_runtime_key_handle_is_valid(right) &&
	       left->slot == right->slot &&
	       left->generation == right->generation &&
	       left->backend == right->backend &&
	       left->family == right->family &&
	       left->level == right->level;
}

int pqcp_runtime_profile_state_init(
	struct pqcp_runtime_profile_state *state,
	const char *profile_id)
{
	if (state == NULL ||
	    !pqcp_runtime_internal_text_valid(
		    profile_id, PQCP_RUNTIME_PROFILE_MAX_CHARS)) {
		return -EINVAL;
	}
	memset(state, 0, sizeof(*state));
	state->schema_version = PQCP_RUNTIME_SCHEMA_VERSION;
	state->latency_source = PQCP_RUNTIME_METRIC_UNKNOWN;
	state->cycles_source = PQCP_RUNTIME_METRIC_UNKNOWN;
	state->memory_source = PQCP_RUNTIME_METRIC_UNKNOWN;
	state->energy_source = PQCP_RUNTIME_METRIC_UNKNOWN;
	return pqcp_runtime_internal_copy_text(
		state->profile_id, sizeof(state->profile_id),
		profile_id);
}

static uint64_t ewma(uint64_t previous, uint64_t observation)
{
	if (previous == 0U) {
		return observation;
	}
	return (previous * 7U + observation) / 8U;
}

int pqcp_runtime_profile_state_observe(
	struct pqcp_runtime_profile_state *state,
	const struct pqcp_runtime_measurement *measurement)
{
	if (state == NULL || measurement == NULL ||
	    state->schema_version != PQCP_RUNTIME_SCHEMA_VERSION ||
	    measurement->schema_version !=
		    PQCP_RUNTIME_SCHEMA_VERSION ||
	    strcmp(state->profile_id,
		   measurement->profile_id) != 0) {
		return -EINVAL;
	}
	state->observation_count++;
	state->last_observed_at_ms =
		measurement->completed_at_ms;
	if (!measurement->success) {
		state->failed_observations++;
		return -EIO;
	}
	state->successful_observations++;
	state->latency_ewma_us = ewma(
		state->latency_ewma_us,
		measurement->latency_us);
	state->cycles_ewma = ewma(
		state->cycles_ewma,
		measurement->cycles);
	if (measurement->stack_used_bytes >
	    state->stack_high_watermark) {
		state->stack_high_watermark =
			measurement->stack_used_bytes;
	}
	if (measurement->workspace_bytes >
	    state->workspace_high_watermark) {
		state->workspace_high_watermark =
			measurement->workspace_bytes;
	}
	state->latency_source =
		state->successful_observations >= 4U ?
		PQCP_RUNTIME_METRIC_CALIBRATED :
		PQCP_RUNTIME_METRIC_MEASURED;
	state->cycles_source = state->latency_source;
	state->memory_source = state->latency_source;
	return 0;
}
