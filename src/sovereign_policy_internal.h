/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#ifndef PQCP_SOVEREIGN_POLICY_INTERNAL_H_
#define PQCP_SOVEREIGN_POLICY_INTERNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/sovereign_policy.h>

bool pqcp_sovereign_policy_text_valid(
	const char *text,
	size_t capacity);
int pqcp_sovereign_policy_copy_text(
	char *destination,
	size_t capacity,
	const char *source);
bool pqcp_sovereign_policy_all_zero(
	const uint8_t *value,
	size_t length);
bool pqcp_sovereign_policy_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length);
uint32_t pqcp_sovereign_policy_next_generation(
	uint32_t *generation);
uint64_t pqcp_sovereign_policy_next_id(uint64_t *identifier);
uint64_t pqcp_sovereign_policy_add_u64(
	uint64_t left,
	uint64_t right);
int pqcp_sovereign_policy_sha256(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);
int pqcp_sovereign_policy_sha256_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES]);
void pqcp_sovereign_policy_write_u16(
	uint8_t output[2],
	uint16_t value);
void pqcp_sovereign_policy_write_u32(
	uint8_t output[4],
	uint32_t value);
void pqcp_sovereign_policy_write_u64(
	uint8_t output[8],
	uint64_t value);

#endif /* PQCP_SOVEREIGN_POLICY_INTERNAL_H_ */
