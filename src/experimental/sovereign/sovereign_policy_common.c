/*
 * SPDX-License-Identifier: MIT
 *
 * Common bounded helpers for sovereign policy services.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <psa/crypto.h>

#include "sovereign_policy_internal.h"

static bool text_character_valid(char value)
{
	return (value >= 'a' && value <= 'z') ||
	       (value >= 'A' && value <= 'Z') ||
	       (value >= '0' && value <= '9') ||
	       value == '-' || value == '_' || value == '.' ||
	       value == ':' || value == '/' || value == '@';
}

bool pqcp_sovereign_policy_text_valid(
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
		if (!text_character_valid(text[index])) {
			return false;
		}
	}
	return true;
}

int pqcp_sovereign_policy_copy_text(
	char *destination,
	size_t capacity,
	const char *source)
{
	size_t length;

	if (destination == NULL || source == NULL ||
	    !pqcp_sovereign_policy_text_valid(source, capacity)) {
		return -EINVAL;
	}
	length = strnlen(source, capacity);
	memcpy(destination, source, length);
	destination[length] = '\0';
	return 0;
}

bool pqcp_sovereign_policy_all_zero(
	const uint8_t *value,
	size_t length)
{
	uint8_t aggregate = 0U;

	if (value == NULL && length != 0U) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		aggregate |= value[index];
	}
	return aggregate == 0U;
}

bool pqcp_sovereign_policy_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length)
{
	uint8_t difference = 0U;

	if ((left == NULL || right == NULL) && length != 0U) {
		return false;
	}
	for (size_t index = 0U; index < length; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

uint32_t pqcp_sovereign_policy_next_generation(
	uint32_t *generation)
{
	if (generation == NULL) {
		return 0U;
	}
	(*generation)++;
	if (*generation == 0U) {
		(*generation)++;
	}
	return *generation;
}

uint64_t pqcp_sovereign_policy_next_id(uint64_t *identifier)
{
	uint64_t result;

	if (identifier == NULL) {
		return 0U;
	}
	result = *identifier;
	if (result == 0U) {
		result = 1U;
	}
	*identifier = result == UINT64_MAX ?
		1U : result + 1U;
	return result;
}

uint64_t pqcp_sovereign_policy_add_u64(
	uint64_t left,
	uint64_t right)
{
	return UINT64_MAX - left < right ?
		UINT64_MAX : left + right;
}

int pqcp_sovereign_policy_sha256(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	size_t output_length = 0U;
	psa_status_t status;

	if ((input == NULL && input_length != 0U) ||
	    output == NULL) {
		return -EINVAL;
	}
	status = psa_hash_compute(
		PSA_ALG_SHA_256, input, input_length,
		output, PQCP_SOVEREIGN_DIGEST_BYTES,
		&output_length);
	if (status != PSA_SUCCESS ||
	    output_length != PQCP_SOVEREIGN_DIGEST_BYTES) {
		if (output != NULL) {
			memset(output, 0,
			       PQCP_SOVEREIGN_DIGEST_BYTES);
		}
		return -EIO;
	}
	return 0;
}

int pqcp_sovereign_policy_sha256_parts(
	const uint8_t *const *parts,
	const size_t *lengths,
	size_t part_count,
	uint8_t output[PQCP_SOVEREIGN_DIGEST_BYTES])
{
	psa_hash_operation_t operation =
		PSA_HASH_OPERATION_INIT;
	size_t output_length = 0U;
	psa_status_t status;

	if (parts == NULL || lengths == NULL ||
	    part_count == 0U || output == NULL) {
		return -EINVAL;
	}
	status = psa_hash_setup(
		&operation, PSA_ALG_SHA_256);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}
	for (size_t index = 0U;
	     index < part_count; ++index) {
		if (parts[index] == NULL &&
		    lengths[index] != 0U) {
			(void)psa_hash_abort(&operation);
			return -EINVAL;
		}
		status = psa_hash_update(
			&operation, parts[index],
			lengths[index]);
		if (status != PSA_SUCCESS) {
			(void)psa_hash_abort(&operation);
			return -EIO;
		}
	}
	status = psa_hash_finish(
		&operation, output,
		PQCP_SOVEREIGN_DIGEST_BYTES,
		&output_length);
	if (status != PSA_SUCCESS ||
	    output_length != PQCP_SOVEREIGN_DIGEST_BYTES) {
		(void)psa_hash_abort(&operation);
		memset(output, 0,
		       PQCP_SOVEREIGN_DIGEST_BYTES);
		return -EIO;
	}
	return 0;
}

void pqcp_sovereign_policy_write_u16(
	uint8_t output[2],
	uint16_t value)
{
	output[0] = (uint8_t)(value >> 8U);
	output[1] = (uint8_t)value;
}

void pqcp_sovereign_policy_write_u32(
	uint8_t output[4],
	uint32_t value)
{
	output[0] = (uint8_t)(value >> 24U);
	output[1] = (uint8_t)(value >> 16U);
	output[2] = (uint8_t)(value >> 8U);
	output[3] = (uint8_t)value;
}

void pqcp_sovereign_policy_write_u64(
	uint8_t output[8],
	uint64_t value)
{
	for (size_t index = 0U; index < 8U; ++index) {
		output[index] =
			(uint8_t)(value >>
			((7U - index) * 8U));
	}
}
