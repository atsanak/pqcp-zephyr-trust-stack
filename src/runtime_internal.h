/*
 * SPDX-License-Identifier: MIT
 */

#ifndef PQCP_RUNTIME_INTERNAL_H_
#define PQCP_RUNTIME_INTERNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/runtime.h>

int pqcp_runtime_internal_copy_text(
	char *destination,
	size_t capacity,
	const char *source);
bool pqcp_runtime_internal_text_valid(
	const char *text,
	size_t capacity);
bool pqcp_runtime_internal_owner_valid(const char *owner);
bool pqcp_runtime_internal_label_valid(const char *label);
bool pqcp_runtime_internal_key_family_valid(
	enum pqcp_runtime_key_family family);
bool pqcp_runtime_internal_key_backend_valid(
	enum pqcp_runtime_key_backend backend);
bool pqcp_runtime_internal_job_type_valid(
	enum pqcp_runtime_job_type type);
bool pqcp_runtime_internal_priority_valid(
	enum pqcp_runtime_job_priority priority);
bool pqcp_runtime_internal_usage_valid(uint32_t usage);
bool pqcp_runtime_internal_level_valid(
	enum pqcp_runtime_key_family family,
	uint32_t level);
size_t pqcp_runtime_internal_public_size(
	enum pqcp_runtime_key_family family,
	uint32_t level);
size_t pqcp_runtime_internal_secret_size(
	enum pqcp_runtime_key_family family,
	uint32_t level);
uint32_t pqcp_runtime_internal_security_level(
	uint32_t mlkem_level,
	uint32_t mldsa_level);
uint64_t pqcp_runtime_internal_now_ms(void);
uint64_t pqcp_runtime_internal_cycles(void);
uint64_t pqcp_runtime_internal_cycles_to_us(uint64_t cycles);
int pqcp_runtime_internal_sha256(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_RUNTIME_DIGEST_BYTES]);
int pqcp_runtime_internal_sha256_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_RUNTIME_DIGEST_BYTES]);
int pqcp_runtime_internal_hex(
	const uint8_t *input,
	size_t input_length,
	char *output,
	size_t output_capacity);
int pqcp_runtime_internal_hmac_sha256(
	const uint8_t *key,
	size_t key_length,
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_RUNTIME_DIGEST_BYTES]);
int pqcp_runtime_internal_hkdf_sha256(
	const uint8_t *salt,
	size_t salt_length,
	const uint8_t *input_key,
	size_t input_key_length,
	const uint8_t *info,
	size_t info_length,
	uint8_t *output,
	size_t output_length);
void pqcp_runtime_internal_write_u16(uint8_t *output, uint16_t value);
void pqcp_runtime_internal_write_u32(uint8_t *output, uint32_t value);
void pqcp_runtime_internal_write_u64(uint8_t *output, uint64_t value);
uint16_t pqcp_runtime_internal_read_u16(const uint8_t *input);
uint32_t pqcp_runtime_internal_read_u32(const uint8_t *input);
uint64_t pqcp_runtime_internal_read_u64(const uint8_t *input);
int pqcp_runtime_internal_profile_id(
	enum pqcp_runtime_key_family family,
	uint32_t mlkem_level,
	uint32_t mldsa_level,
	char output[PQCP_RUNTIME_PROFILE_MAX_CHARS]);

#endif /* PQCP_RUNTIME_INTERNAL_H_ */
