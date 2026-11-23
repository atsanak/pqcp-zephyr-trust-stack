/*
 * SPDX-License-Identifier: MIT
 *
 * Small hosted/firmware-neutral SHA-256 implementation for fleet identifiers.
 */

#include <errno.h>
#include <string.h>

#include "fleet_internal.h"

struct sha256_state {
	uint32_t state[8];
	uint64_t bit_count;
	uint8_t block[64];
	size_t block_length;
};

static const uint32_t round_constants[64] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
	0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
	0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
	0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
	0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
	0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
	0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
	0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
	0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
	0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
	0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
	0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
	0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
	0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
	0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t rotate_right(uint32_t value, uint32_t shift)
{
	return (value >> shift) | (value << (32U - shift));
}

static uint32_t read_be32(const uint8_t *input)
{
	return ((uint32_t)input[0] << 24) |
	       ((uint32_t)input[1] << 16) |
	       ((uint32_t)input[2] << 8) |
	       input[3];
}

static void write_be32(uint8_t *output, uint32_t value)
{
	output[0] = (uint8_t)(value >> 24);
	output[1] = (uint8_t)(value >> 16);
	output[2] = (uint8_t)(value >> 8);
	output[3] = (uint8_t)value;
}

static void transform(
	struct sha256_state *state,
	const uint8_t block[64])
{
	uint32_t words[64];
	uint32_t a = state->state[0];
	uint32_t b = state->state[1];
	uint32_t c = state->state[2];
	uint32_t d = state->state[3];
	uint32_t e = state->state[4];
	uint32_t f = state->state[5];
	uint32_t g = state->state[6];
	uint32_t h = state->state[7];

	for (size_t index = 0U; index < 16U; ++index) {
		words[index] = read_be32(block + index * 4U);
	}
	for (size_t index = 16U; index < 64U; ++index) {
		const uint32_t s0 =
			rotate_right(words[index - 15U], 7U) ^
			rotate_right(words[index - 15U], 18U) ^
			(words[index - 15U] >> 3);
		const uint32_t s1 =
			rotate_right(words[index - 2U], 17U) ^
			rotate_right(words[index - 2U], 19U) ^
			(words[index - 2U] >> 10);

		words[index] = words[index - 16U] + s0 +
			words[index - 7U] + s1;
	}
	for (size_t index = 0U; index < 64U; ++index) {
		const uint32_t sum1 =
			rotate_right(e, 6U) ^
			rotate_right(e, 11U) ^
			rotate_right(e, 25U);
		const uint32_t choice =
			(e & f) ^ ((~e) & g);
		const uint32_t temporary1 =
			h + sum1 + choice +
			round_constants[index] + words[index];
		const uint32_t sum0 =
			rotate_right(a, 2U) ^
			rotate_right(a, 13U) ^
			rotate_right(a, 22U);
		const uint32_t majority =
			(a & b) ^ (a & c) ^ (b & c);
		const uint32_t temporary2 = sum0 + majority;

		h = g;
		g = f;
		f = e;
		e = d + temporary1;
		d = c;
		c = b;
		b = a;
		a = temporary1 + temporary2;
	}
	state->state[0] += a;
	state->state[1] += b;
	state->state[2] += c;
	state->state[3] += d;
	state->state[4] += e;
	state->state[5] += f;
	state->state[6] += g;
	state->state[7] += h;
}

static void sha256_init(struct sha256_state *state)
{
	memset(state, 0, sizeof(*state));
	state->state[0] = 0x6a09e667U;
	state->state[1] = 0xbb67ae85U;
	state->state[2] = 0x3c6ef372U;
	state->state[3] = 0xa54ff53aU;
	state->state[4] = 0x510e527fU;
	state->state[5] = 0x9b05688cU;
	state->state[6] = 0x1f83d9abU;
	state->state[7] = 0x5be0cd19U;
}

static void sha256_update(
	struct sha256_state *state,
	const uint8_t *input,
	size_t input_length)
{
	while (input_length != 0U) {
		size_t available = sizeof(state->block) -
			state->block_length;
		size_t copied = input_length < available ?
			input_length : available;

		memcpy(state->block + state->block_length,
		       input, copied);
		state->block_length += copied;
		state->bit_count += copied * 8U;
		input += copied;
		input_length -= copied;
		if (state->block_length == sizeof(state->block)) {
			transform(state, state->block);
			state->block_length = 0U;
		}
	}
}

static void sha256_final(
	struct sha256_state *state,
	uint8_t output[PQCP_FLEET_DIGEST_BYTES])
{
	state->block[state->block_length++] = 0x80U;
	if (state->block_length > 56U) {
		memset(state->block + state->block_length, 0,
		       sizeof(state->block) - state->block_length);
		transform(state, state->block);
		state->block_length = 0U;
	}
	memset(state->block + state->block_length, 0,
	       56U - state->block_length);
	for (size_t index = 0U; index < 8U; ++index) {
		state->block[63U - index] =
			(uint8_t)(state->bit_count >> (index * 8U));
	}
	transform(state, state->block);
	for (size_t index = 0U; index < 8U; ++index) {
		write_be32(output + index * 4U,
			   state->state[index]);
	}
	memset(state, 0, sizeof(*state));
}

int pqcp_fleet_sha256(
	const uint8_t *input,
	size_t input_length,
	uint8_t output[PQCP_FLEET_DIGEST_BYTES])
{
	struct sha256_state state;

	if ((input == NULL && input_length != 0U) ||
	    output == NULL) {
		return -EINVAL;
	}
	sha256_init(&state);
	sha256_update(&state, input, input_length);
	sha256_final(&state, output);
	return 0;
}
