/*
 * SPDX-License-Identifier: MIT
 */

#ifndef PQCP_EDGE_SECURITY_INTERNAL_H_
#define PQCP_EDGE_SECURITY_INTERNAL_H_

#include <limits.h>

#include <pqcp_zephyr/edge_security.h>
#include <pqcp_zephyr/errno.h>

bool pqcp_edge_internal_all_zero(
	const uint8_t *value,
	size_t length);
bool pqcp_edge_internal_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length);
bool pqcp_edge_internal_text_valid(
	const char *value,
	size_t capacity);
int pqcp_edge_internal_copy_text(
	char *destination,
	size_t capacity,
	const char *source);
uint32_t pqcp_edge_internal_next_generation(
	uint32_t *generation);
uint64_t pqcp_edge_internal_next_identifier(
	uint64_t *identifier);
uint64_t pqcp_edge_internal_saturating_add_u64(
	uint64_t left,
	uint64_t right);
uint32_t pqcp_edge_internal_saturating_add_u32(
	uint32_t left,
	uint32_t right);
uint64_t pqcp_edge_internal_backoff(
	uint64_t base_ms,
	uint64_t maximum_ms,
	uint32_t attempt);
int pqcp_edge_internal_sha256(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES]);
int pqcp_edge_internal_sha256_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES]);
int pqcp_edge_internal_hmac(
	const uint8_t key[PQCP_EDGE_KEY_BYTES],
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_EDGE_TAG_BYTES]);
int pqcp_edge_internal_hkdf(
	const uint8_t salt[PQCP_EDGE_KEY_BYTES],
	const uint8_t input_key[PQCP_EDGE_KEY_BYTES],
	const uint8_t *info,
	size_t info_length,
	uint8_t output[PQCP_EDGE_KEY_BYTES]);
void pqcp_edge_internal_write_u16(
	uint8_t output[2],
	uint16_t value);
void pqcp_edge_internal_write_u32(
	uint8_t output[4],
	uint32_t value);
void pqcp_edge_internal_write_u64(
	uint8_t output[8],
	uint64_t value);
uint16_t pqcp_edge_internal_read_u16(
	const uint8_t input[2]);
uint32_t pqcp_edge_internal_read_u32(
	const uint8_t input[4]);
uint64_t pqcp_edge_internal_read_u64(
	const uint8_t input[8]);
int pqcp_edge_internal_object_digest(
	const struct pqcp_edge_vault_object *object,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES]);
int pqcp_edge_internal_incident_digest(
	const struct pqcp_edge_incident *incident,
	uint8_t output[PQCP_EDGE_DIGEST_BYTES]);

#endif /* PQCP_EDGE_SECURITY_INTERNAL_H_ */
