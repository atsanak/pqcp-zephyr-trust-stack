/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Deterministic, allocation-free fleet policy module codec.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pqcp_zephyr/fleet_policy_vm.h>

#define POLICY_WIRE_MAGIC UINT32_C(0x5051504d)
#define POLICY_WIRE_HEADER_BYTES 104U
#define POLICY_WIRE_INSTRUCTION_BYTES 8U
#define POLICY_WIRE_FUNCTION_BYTES 16U
#define POLICY_WIRE_CONSTANT_HEADER_BYTES 8U
#define POLICY_WIRE_ALIGNMENT 8U
#define POLICY_WIRE_DIGEST_OFFSET 72U

#define POLICY_MODULE_KNOWN_FLAGS \
	(PQCP_FLEET_POLICY_MODULE_REQUIRE_DIGEST | \
	 PQCP_FLEET_POLICY_MODULE_CANONICAL)

struct codec_sink {
	void *context;
	int (*write)(void *context, const uint8_t *data, size_t length);
	size_t offset;
	int status;
};

struct buffer_sink {
	uint8_t *output;
	size_t capacity;
};

struct sha256_state {
	uint32_t state[8];
	uint64_t bit_count;
	uint8_t block[64];
	size_t block_length;
};

struct decode_cursor {
	const uint8_t *input;
	size_t length;
	size_t offset;
	size_t fault_offset;
	int status;
};

struct decoded_header {
	uint32_t total_size;
	uint32_t abi_version;
	uint32_t bytecode_version;
	uint32_t flags;
	uint32_t entry_function;
	uint32_t instruction_count;
	uint32_t constant_count;
	uint32_t function_count;
	struct pqcp_fleet_policy_bounds bounds;
	uint32_t instructions_offset;
	uint32_t constants_offset;
	uint32_t functions_offset;
	uint8_t digest[PQCP_FLEET_POLICY_DIGEST_BYTES];
};

static const uint32_t sha256_round_constants[64] = {
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

static uint32_t load_be32(const uint8_t *input)
{
	return ((uint32_t)input[0] << 24) |
	       ((uint32_t)input[1] << 16) |
	       ((uint32_t)input[2] << 8) |
	       (uint32_t)input[3];
}

static uint64_t load_be64(const uint8_t *input)
{
	uint64_t value = 0U;

	for (size_t index = 0U; index < 8U; ++index) {
		value = (value << 8) | input[index];
	}
	return value;
}

/*
 * Signed constants use zig-zag representation. This avoids relying on the
 * host's signed integer representation or implementation-defined unsigned to
 * signed conversions while preserving a unique encoding for every int64_t.
 */
static uint64_t encode_i64(int64_t value)
{
	if (value >= 0) {
		return (uint64_t)value << 1;
	}
	return ((uint64_t)(-(value + 1)) << 1) | 1U;
}

static int64_t decode_i64(uint64_t value)
{
	const uint64_t magnitude = value >> 1;

	if ((value & 1U) == 0U) {
		return (int64_t)magnitude;
	}
	return -(int64_t)magnitude - 1;
}

static void store_be16(uint8_t output[2], uint16_t value)
{
	output[0] = (uint8_t)(value >> 8);
	output[1] = (uint8_t)value;
}

static void store_be32(uint8_t output[4], uint32_t value)
{
	output[0] = (uint8_t)(value >> 24);
	output[1] = (uint8_t)(value >> 16);
	output[2] = (uint8_t)(value >> 8);
	output[3] = (uint8_t)value;
}

static void store_be64(uint8_t output[8], uint64_t value)
{
	for (size_t index = 0U; index < 8U; ++index) {
		output[7U - index] = (uint8_t)(value >> (index * 8U));
	}
}

static void sha256_transform(
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
		words[index] = load_be32(block + index * 4U);
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
			sha256_round_constants[index] + words[index];
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
	memset(words, 0, sizeof(words));
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
		const size_t available =
			sizeof(state->block) - state->block_length;
		const size_t copied =
			input_length < available ? input_length : available;

		memcpy(state->block + state->block_length, input, copied);
		state->block_length += copied;
		state->bit_count += (uint64_t)copied * 8U;
		input += copied;
		input_length -= copied;
		if (state->block_length == sizeof(state->block)) {
			sha256_transform(state, state->block);
			state->block_length = 0U;
		}
	}
}

static void sha256_final(
	struct sha256_state *state,
	uint8_t output[PQCP_FLEET_POLICY_DIGEST_BYTES])
{
	state->block[state->block_length++] = 0x80U;
	if (state->block_length > 56U) {
		memset(state->block + state->block_length, 0,
		       sizeof(state->block) - state->block_length);
		sha256_transform(state, state->block);
		state->block_length = 0U;
	}
	memset(state->block + state->block_length, 0,
	       56U - state->block_length);
	store_be64(state->block + 56U, state->bit_count);
	sha256_transform(state, state->block);
	for (size_t index = 0U; index < 8U; ++index) {
		store_be32(output + index * 4U, state->state[index]);
	}
	memset(state, 0, sizeof(*state));
}

static int buffer_write(
	void *context,
	const uint8_t *data,
	size_t length)
{
	struct buffer_sink *buffer = context;

	if (length > buffer->capacity) {
		return PQCP_FLEET_POLICY_ERR_CAPACITY;
	}
	if (length != 0U) {
		memcpy(buffer->output, data, length);
		buffer->output += length;
		buffer->capacity -= length;
	}
	return PQCP_FLEET_POLICY_OK;
}

static int sha256_write(
	void *context,
	const uint8_t *data,
	size_t length)
{
	sha256_update(context, data, length);
	return PQCP_FLEET_POLICY_OK;
}

static int sink_write(
	struct codec_sink *sink,
	const uint8_t *data,
	size_t length)
{
	if (sink->status != PQCP_FLEET_POLICY_OK) {
		return sink->status;
	}
	if (SIZE_MAX - sink->offset < length) {
		sink->status = PQCP_FLEET_POLICY_ERR_OVERFLOW;
		return sink->status;
	}
	if (sink->write != NULL) {
		sink->status = sink->write(sink->context, data, length);
		if (sink->status != PQCP_FLEET_POLICY_OK) {
			return sink->status;
		}
	}
	sink->offset += length;
	return PQCP_FLEET_POLICY_OK;
}

static int sink_zeros(struct codec_sink *sink, size_t length)
{
	static const uint8_t zeros[POLICY_WIRE_ALIGNMENT] = {0};

	while (length != 0U && sink->status == PQCP_FLEET_POLICY_OK) {
		const size_t chunk =
			length < sizeof(zeros) ? length : sizeof(zeros);

		(void)sink_write(sink, zeros, chunk);
		length -= chunk;
	}
	return sink->status;
}

static int sink_u8(struct codec_sink *sink, uint8_t value)
{
	return sink_write(sink, &value, sizeof(value));
}

static int sink_u16(struct codec_sink *sink, uint16_t value)
{
	uint8_t encoded[2];

	store_be16(encoded, value);
	return sink_write(sink, encoded, sizeof(encoded));
}

static int sink_u32(struct codec_sink *sink, uint32_t value)
{
	uint8_t encoded[4];

	store_be32(encoded, value);
	return sink_write(sink, encoded, sizeof(encoded));
}

static int sink_u64(struct codec_sink *sink, uint64_t value)
{
	uint8_t encoded[8];

	store_be64(encoded, value);
	return sink_write(sink, encoded, sizeof(encoded));
}

static bool digest_equal(
	const uint8_t left[PQCP_FLEET_POLICY_DIGEST_BYTES],
	const uint8_t right[PQCP_FLEET_POLICY_DIGEST_BYTES])
{
	uint8_t difference = 0U;

	for (size_t index = 0U;
	     index < PQCP_FLEET_POLICY_DIGEST_BYTES; ++index) {
		difference |= left[index] ^ right[index];
	}
	return difference == 0U;
}

static bool multiply_size(
	size_t left,
	size_t right,
	size_t *result)
{
	if (left != 0U && right > SIZE_MAX / left) {
		return false;
	}
	*result = left * right;
	return true;
}

static bool add_size(size_t left, size_t right, size_t *result)
{
	if (right > SIZE_MAX - left) {
		return false;
	}
	*result = left + right;
	return true;
}

static bool align_size(size_t value, size_t *aligned)
{
	const size_t remainder = value % POLICY_WIRE_ALIGNMENT;
	const size_t padding =
		remainder == 0U ? 0U : POLICY_WIRE_ALIGNMENT - remainder;

	return add_size(value, padding, aligned);
}

static int constant_payload_length(
	const struct pqcp_fleet_policy_value *value,
	uint32_t *payload_length)
{
	if (value == NULL || payload_length == NULL ||
	    value->reserved != 0U) {
		return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
	}
	switch (value->type) {
	case PQCP_FLEET_POLICY_VALUE_I64:
	case PQCP_FLEET_POLICY_VALUE_U64:
		*payload_length = 8U;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_VALUE_BOOL:
		*payload_length = 1U;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_VALUE_BYTES:
		if (value->as.bytes.length != 0U &&
		    value->as.bytes.data == NULL) {
			return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
		}
		*payload_length = value->as.bytes.length;
		return PQCP_FLEET_POLICY_OK;
	case PQCP_FLEET_POLICY_VALUE_DIGEST:
		if (value->as.bytes.data == NULL ||
		    value->as.bytes.length !=
			    PQCP_FLEET_POLICY_DIGEST_BYTES) {
			return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
		}
		*payload_length = PQCP_FLEET_POLICY_DIGEST_BYTES;
		return PQCP_FLEET_POLICY_OK;
	default:
		return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
	}
}

static int module_size_and_offsets(
	const struct pqcp_fleet_policy_module *module,
	size_t *encoded_size,
	uint32_t *instructions_offset,
	uint32_t *constants_offset,
	uint32_t *functions_offset)
{
	size_t instruction_bytes;
	size_t function_bytes;
	size_t total = POLICY_WIRE_HEADER_BYTES;
	size_t constants_start;
	size_t functions_start;
	size_t aligned;
	uint32_t next_instruction = 0U;
	uint32_t entry_flags = 0U;

	if (module == NULL || encoded_size == NULL ||
	    module->abi_version != PQCP_FLEET_POLICY_ABI_VERSION ||
	    module->bytecode_version !=
		    PQCP_FLEET_POLICY_BYTECODE_VERSION ||
	    (module->flags & ~POLICY_MODULE_KNOWN_FLAGS) != 0U ||
	    module->instruction_count == 0U ||
	    module->function_count == 0U ||
	    module->entry_function >= module->function_count ||
	    module->instructions == NULL ||
	    module->functions == NULL ||
	    (module->constant_count != 0U &&
	     module->constants == NULL) ||
	    module->bounds.instruction_budget == 0U ||
	    module->bounds.max_stack_values == 0U ||
	    module->bounds.max_call_frames == 0U ||
	    module->bounds.max_action_arguments >
		    PQCP_FLEET_POLICY_MAX_ACTION_ARGS ||
	    module->bounds.reserved != 0U) {
		return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
	}
	for (uint32_t index = 0U;
	     index < module->instruction_count; ++index) {
		if (module->instructions[index].opcode >=
		    PQCP_FLEET_POLICY_OP_COUNT) {
			return PQCP_FLEET_POLICY_ERR_BAD_OPCODE;
		}
	}
	if (!multiply_size(module->instruction_count,
			   POLICY_WIRE_INSTRUCTION_BYTES,
			   &instruction_bytes) ||
	    !add_size(total, instruction_bytes, &total)) {
		return PQCP_FLEET_POLICY_ERR_OVERFLOW;
	}
	constants_start = total;
	for (uint32_t index = 0U;
	     index < module->constant_count; ++index) {
		uint32_t payload_length;
		size_t record_size;
		int status = constant_payload_length(
			&module->constants[index], &payload_length);

		if (status != PQCP_FLEET_POLICY_OK) {
			return status;
		}
		if (!add_size(POLICY_WIRE_CONSTANT_HEADER_BYTES,
			      payload_length, &record_size) ||
		    !align_size(record_size, &aligned) ||
		    !add_size(total, aligned, &total)) {
			return PQCP_FLEET_POLICY_ERR_OVERFLOW;
		}
	}
	functions_start = total;
	if (!multiply_size(module->function_count,
			   POLICY_WIRE_FUNCTION_BYTES,
			   &function_bytes) ||
	    !add_size(total, function_bytes, &total) ||
	    total > UINT32_MAX ||
	    constants_start > UINT32_MAX ||
	    functions_start > UINT32_MAX) {
		return PQCP_FLEET_POLICY_ERR_OVERFLOW;
	}
	for (uint32_t index = 0U;
	     index < module->function_count; ++index) {
		const struct pqcp_fleet_policy_function *function =
			&module->functions[index];
		const uint32_t known_flags =
			PQCP_FLEET_POLICY_FUNCTION_ENTRY;

		if (function->instruction_count == 0U ||
		    function->first_instruction != next_instruction ||
		    function->instruction_count >
			    module->instruction_count -
				    function->first_instruction ||
		    function->parameter_count > function->local_count ||
		    function->result_count > 1U ||
		    (function->flags & ~known_flags) != 0U ||
		    function->reserved != 0U) {
			return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
		}
		if ((function->flags &
		     PQCP_FLEET_POLICY_FUNCTION_ENTRY) != 0U) {
			entry_flags++;
			if (index != module->entry_function ||
			    function->parameter_count != 0U ||
			    function->result_count != 0U) {
				return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
			}
		}
		next_instruction += function->instruction_count;
	}
	if (next_instruction != module->instruction_count ||
	    entry_flags != 1U) {
		return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
	}
	*encoded_size = total;
	if (instructions_offset != NULL) {
		*instructions_offset = POLICY_WIRE_HEADER_BYTES;
	}
	if (constants_offset != NULL) {
		*constants_offset = (uint32_t)constants_start;
	}
	if (functions_offset != NULL) {
		*functions_offset = (uint32_t)functions_start;
	}
	return PQCP_FLEET_POLICY_OK;
}

static int emit_constant(
	struct codec_sink *sink,
	const struct pqcp_fleet_policy_value *value)
{
	uint32_t payload_length;
	size_t record_size;
	size_t aligned_size;
	int status = constant_payload_length(value, &payload_length);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	if (!add_size(POLICY_WIRE_CONSTANT_HEADER_BYTES,
		      payload_length, &record_size) ||
	    !align_size(record_size, &aligned_size)) {
		return PQCP_FLEET_POLICY_ERR_OVERFLOW;
	}
	(void)sink_u32(sink, value->type);
	(void)sink_u32(sink, payload_length);
	switch (value->type) {
	case PQCP_FLEET_POLICY_VALUE_I64:
		(void)sink_u64(sink, encode_i64(value->as.i64));
		break;
	case PQCP_FLEET_POLICY_VALUE_U64:
		(void)sink_u64(sink, value->as.u64);
		break;
	case PQCP_FLEET_POLICY_VALUE_BOOL:
		(void)sink_u8(sink, value->as.boolean ? 1U : 0U);
		break;
	case PQCP_FLEET_POLICY_VALUE_BYTES:
	case PQCP_FLEET_POLICY_VALUE_DIGEST:
		(void)sink_write(sink, value->as.bytes.data,
				 value->as.bytes.length);
		break;
	default:
		return PQCP_FLEET_POLICY_ERR_BAD_MODULE;
	}
	if (sink->status == PQCP_FLEET_POLICY_OK) {
		(void)sink_zeros(sink, aligned_size - record_size);
	}
	return sink->status;
}

static int emit_module(
	const struct pqcp_fleet_policy_module *module,
	struct codec_sink *sink,
	const uint8_t digest[PQCP_FLEET_POLICY_DIGEST_BYTES])
{
	size_t encoded_size;
	uint32_t instructions_offset;
	uint32_t constants_offset;
	uint32_t functions_offset;
	int status = module_size_and_offsets(
		module, &encoded_size, &instructions_offset,
		&constants_offset, &functions_offset);

	if (status != PQCP_FLEET_POLICY_OK) {
		return status;
	}
	(void)sink_u32(sink, POLICY_WIRE_MAGIC);
	(void)sink_u32(sink, PQCP_FLEET_POLICY_WIRE_VERSION);
	(void)sink_u32(sink, POLICY_WIRE_HEADER_BYTES);
	(void)sink_u32(sink, (uint32_t)encoded_size);
	(void)sink_u32(sink, module->abi_version);
	(void)sink_u32(sink, module->bytecode_version);
	(void)sink_u32(sink, module->flags);
	(void)sink_u32(sink, module->entry_function);
	(void)sink_u32(sink, module->instruction_count);
	(void)sink_u32(sink, module->constant_count);
	(void)sink_u32(sink, module->function_count);
	(void)sink_u32(sink, module->bounds.instruction_budget);
	(void)sink_u16(sink, module->bounds.max_stack_values);
	(void)sink_u16(sink, module->bounds.max_call_frames);
	(void)sink_u16(sink, module->bounds.max_local_values);
	(void)sink_u16(sink, module->bounds.max_actions);
	(void)sink_u16(sink, module->bounds.max_action_arguments);
	(void)sink_u16(sink, 0U);
	(void)sink_u32(sink, instructions_offset);
	(void)sink_u32(sink, constants_offset);
	(void)sink_u32(sink, functions_offset);
	if (digest == NULL) {
		(void)sink_zeros(sink, PQCP_FLEET_POLICY_DIGEST_BYTES);
	} else {
		(void)sink_write(sink, digest,
				 PQCP_FLEET_POLICY_DIGEST_BYTES);
	}
	for (uint32_t index = 0U;
	     sink->status == PQCP_FLEET_POLICY_OK &&
	     index < module->instruction_count; ++index) {
		const struct pqcp_fleet_policy_instruction *instruction =
			&module->instructions[index];

		(void)sink_u8(sink, instruction->opcode);
		(void)sink_u8(sink, instruction->a);
		(void)sink_u16(sink, instruction->b);
		(void)sink_u32(sink, instruction->immediate);
	}
	for (uint32_t index = 0U;
	     sink->status == PQCP_FLEET_POLICY_OK &&
	     index < module->constant_count; ++index) {
		status = emit_constant(sink, &module->constants[index]);
		if (status != PQCP_FLEET_POLICY_OK) {
			return status;
		}
	}
	for (uint32_t index = 0U;
	     sink->status == PQCP_FLEET_POLICY_OK &&
	     index < module->function_count; ++index) {
		const struct pqcp_fleet_policy_function *function =
			&module->functions[index];

		(void)sink_u32(sink, function->first_instruction);
		(void)sink_u32(sink, function->instruction_count);
		(void)sink_u16(sink, function->parameter_count);
		(void)sink_u16(sink, function->local_count);
		(void)sink_u8(sink, function->result_count);
		(void)sink_u8(sink, function->flags);
		(void)sink_u16(sink, 0U);
	}
	if (sink->status != PQCP_FLEET_POLICY_OK) {
		return sink->status;
	}
	if (sink->offset != encoded_size) {
		return PQCP_FLEET_POLICY_ERR_CODEC;
	}
	return PQCP_FLEET_POLICY_OK;
}

static void result_reset(struct pqcp_fleet_policy_codec_result *result)
{
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
		result->status = PQCP_FLEET_POLICY_OK;
	}
}

static int result_fail(
	struct pqcp_fleet_policy_codec_result *result,
	int status,
	size_t consumed,
	size_t produced,
	size_t fault_offset)
{
	if (result != NULL) {
		result->status = status;
		result->bytes_consumed = consumed;
		result->bytes_produced = produced;
		result->fault_offset =
			fault_offset > UINT32_MAX ?
				UINT32_MAX : (uint32_t)fault_offset;
	}
	return status;
}

static int digest_module(
	const struct pqcp_fleet_policy_module *module,
	uint8_t digest[PQCP_FLEET_POLICY_DIGEST_BYTES])
{
	struct sha256_state sha256;
	struct codec_sink sink = {
		.context = &sha256,
		.write = sha256_write,
		.offset = 0U,
		.status = PQCP_FLEET_POLICY_OK,
	};
	int status;

	sha256_init(&sha256);
	status = emit_module(module, &sink, NULL);
	if (status == PQCP_FLEET_POLICY_OK) {
		sha256_final(&sha256, digest);
	} else {
		memset(&sha256, 0, sizeof(sha256));
	}
	return status;
}

static void cursor_fail(
	struct decode_cursor *cursor,
	int status,
	size_t fault_offset)
{
	if (cursor->status == PQCP_FLEET_POLICY_OK) {
		cursor->status = status;
		cursor->fault_offset = fault_offset;
	}
}

static const uint8_t *cursor_take(
	struct decode_cursor *cursor,
	size_t length)
{
	const uint8_t *value;

	if (cursor->status != PQCP_FLEET_POLICY_OK) {
		return NULL;
	}
	if (length > cursor->length - cursor->offset) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
			    cursor->offset);
		return NULL;
	}
	value = cursor->input + cursor->offset;
	cursor->offset += length;
	return value;
}

static uint8_t cursor_u8(struct decode_cursor *cursor)
{
	const uint8_t *encoded = cursor_take(cursor, 1U);

	return encoded == NULL ? 0U : encoded[0];
}

static uint16_t cursor_u16(struct decode_cursor *cursor)
{
	const uint8_t *encoded = cursor_take(cursor, 2U);

	if (encoded == NULL) {
		return 0U;
	}
	return ((uint16_t)encoded[0] << 8) | encoded[1];
}

static uint32_t cursor_u32(struct decode_cursor *cursor)
{
	const uint8_t *encoded = cursor_take(cursor, 4U);

	return encoded == NULL ? 0U : load_be32(encoded);
}

static int cursor_zero_padding(
	struct decode_cursor *cursor,
	size_t length)
{
	const size_t start = cursor->offset;
	const uint8_t *padding = cursor_take(cursor, length);

	if (padding == NULL) {
		return cursor->status;
	}
	for (size_t index = 0U; index < length; ++index) {
		if (padding[index] != 0U) {
			cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
				    start + index);
			break;
		}
	}
	return cursor->status;
}

static int decode_header(
	struct decode_cursor *cursor,
	struct decoded_header *header)
{
	const size_t digest_offset = POLICY_WIRE_DIGEST_OFFSET;

	if (cursor_u32(cursor) != POLICY_WIRE_MAGIC) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC, 0U);
	}
	if (cursor_u32(cursor) != PQCP_FLEET_POLICY_WIRE_VERSION) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC, 4U);
	}
	if (cursor_u32(cursor) != POLICY_WIRE_HEADER_BYTES) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC, 8U);
	}
	header->total_size = cursor_u32(cursor);
	header->abi_version = cursor_u32(cursor);
	header->bytecode_version = cursor_u32(cursor);
	header->flags = cursor_u32(cursor);
	header->entry_function = cursor_u32(cursor);
	header->instruction_count = cursor_u32(cursor);
	header->constant_count = cursor_u32(cursor);
	header->function_count = cursor_u32(cursor);
	header->bounds.instruction_budget = cursor_u32(cursor);
	header->bounds.max_stack_values = cursor_u16(cursor);
	header->bounds.max_call_frames = cursor_u16(cursor);
	header->bounds.max_local_values = cursor_u16(cursor);
	header->bounds.max_actions = cursor_u16(cursor);
	header->bounds.max_action_arguments = cursor_u16(cursor);
	header->bounds.reserved = cursor_u16(cursor);
	header->instructions_offset = cursor_u32(cursor);
	header->constants_offset = cursor_u32(cursor);
	header->functions_offset = cursor_u32(cursor);
	const uint8_t *digest = cursor_take(
		cursor, PQCP_FLEET_POLICY_DIGEST_BYTES);

	if (digest != NULL) {
		memcpy(header->digest, digest, sizeof(header->digest));
	}
	if (cursor->status != PQCP_FLEET_POLICY_OK) {
		return cursor->status;
	}
	if (header->total_size != cursor->length ||
	    header->total_size < POLICY_WIRE_HEADER_BYTES ||
	    header->abi_version != PQCP_FLEET_POLICY_ABI_VERSION ||
	    header->bytecode_version !=
		    PQCP_FLEET_POLICY_BYTECODE_VERSION ||
	    (header->flags & ~POLICY_MODULE_KNOWN_FLAGS) != 0U ||
	    header->instruction_count == 0U ||
	    header->function_count == 0U ||
	    header->entry_function >= header->function_count ||
	    header->bounds.instruction_budget == 0U ||
	    header->bounds.max_stack_values == 0U ||
	    header->bounds.max_call_frames == 0U ||
	    header->bounds.max_action_arguments >
		    PQCP_FLEET_POLICY_MAX_ACTION_ARGS ||
	    header->bounds.reserved != 0U ||
	    header->instructions_offset != POLICY_WIRE_HEADER_BYTES ||
	    header->constants_offset < header->instructions_offset ||
	    header->functions_offset < header->constants_offset) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_BAD_MODULE,
			    digest_offset);
	}
	return cursor->status;
}

static int decode_instructions(
	struct decode_cursor *cursor,
	const struct decoded_header *header,
	struct pqcp_fleet_policy_instruction *instructions)
{
	size_t instruction_bytes;
	size_t expected_constants_offset;

	if (!multiply_size(header->instruction_count,
			   POLICY_WIRE_INSTRUCTION_BYTES,
			   &instruction_bytes) ||
	    !add_size(POLICY_WIRE_HEADER_BYTES, instruction_bytes,
		      &expected_constants_offset) ||
	    expected_constants_offset != header->constants_offset) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
			    cursor->offset);
		return cursor->status;
	}
	for (uint32_t index = 0U;
	     index < header->instruction_count &&
	     cursor->status == PQCP_FLEET_POLICY_OK; ++index) {
		struct pqcp_fleet_policy_instruction instruction;
		const size_t start = cursor->offset;

		instruction.opcode = cursor_u8(cursor);
		instruction.a = cursor_u8(cursor);
		instruction.b = cursor_u16(cursor);
		instruction.immediate = cursor_u32(cursor);
		if (instruction.opcode >= PQCP_FLEET_POLICY_OP_COUNT) {
			cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_BAD_OPCODE,
				    start);
		}
		if (instructions != NULL &&
		    cursor->status == PQCP_FLEET_POLICY_OK) {
			instructions[index] = instruction;
		}
	}
	return cursor->status;
}

static int decode_constant(
	struct decode_cursor *cursor,
	struct pqcp_fleet_policy_value *value)
{
	const size_t record_start = cursor->offset;
	const uint32_t type = cursor_u32(cursor);
	const uint32_t payload_length = cursor_u32(cursor);
	size_t record_size;
	size_t aligned_size;
	const uint8_t *payload;

	if (!add_size(POLICY_WIRE_CONSTANT_HEADER_BYTES,
		      payload_length, &record_size) ||
	    !align_size(record_size, &aligned_size)) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_OVERFLOW,
			    record_start + 4U);
		return cursor->status;
	}
	payload = cursor_take(cursor, payload_length);
	if (payload == NULL) {
		return cursor->status;
	}
	struct pqcp_fleet_policy_value decoded = {
		.type = type,
		.reserved = 0U,
	};

	switch (type) {
	case PQCP_FLEET_POLICY_VALUE_I64:
		if (payload_length != 8U) {
			cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
				    record_start + 4U);
		} else {
			decoded.as.i64 = decode_i64(load_be64(payload));
		}
		break;
	case PQCP_FLEET_POLICY_VALUE_U64:
		if (payload_length != 8U) {
			cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
				    record_start + 4U);
		} else {
			decoded.as.u64 = load_be64(payload);
		}
		break;
	case PQCP_FLEET_POLICY_VALUE_BOOL:
		if (payload_length != 1U ||
		    (payload[0] != 0U && payload[0] != 1U)) {
			cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
				    record_start + 4U);
		} else {
			decoded.as.boolean = payload[0] != 0U;
		}
		break;
	case PQCP_FLEET_POLICY_VALUE_BYTES:
		decoded.as.bytes.data = payload_length == 0U ?
			NULL : payload;
		decoded.as.bytes.length = payload_length;
		break;
	case PQCP_FLEET_POLICY_VALUE_DIGEST:
		if (payload_length != PQCP_FLEET_POLICY_DIGEST_BYTES) {
			cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
				    record_start + 4U);
		} else {
			decoded.as.bytes.data = payload;
			decoded.as.bytes.length = payload_length;
		}
		break;
	default:
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
			    record_start);
		break;
	}
	if (cursor->status == PQCP_FLEET_POLICY_OK) {
		(void)cursor_zero_padding(
			cursor, aligned_size - record_size);
	}
	if (value != NULL &&
	    cursor->status == PQCP_FLEET_POLICY_OK) {
		*value = decoded;
	}
	return cursor->status;
}

static int decode_constants(
	struct decode_cursor *cursor,
	const struct decoded_header *header,
	struct pqcp_fleet_policy_value *constants)
{
	if (cursor->offset != header->constants_offset) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
			    cursor->offset);
		return cursor->status;
	}
	for (uint32_t index = 0U;
	     index < header->constant_count &&
	     cursor->status == PQCP_FLEET_POLICY_OK; ++index) {
		(void)decode_constant(
			cursor,
			constants == NULL ? NULL : &constants[index]);
	}
	if (cursor->status == PQCP_FLEET_POLICY_OK &&
	    cursor->offset != header->functions_offset) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
			    cursor->offset);
	}
	return cursor->status;
}

static int decode_functions(
	struct decode_cursor *cursor,
	const struct decoded_header *header,
	struct pqcp_fleet_policy_function *functions)
{
	size_t function_bytes;
	size_t expected_end;
	uint32_t next_instruction = 0U;
	uint32_t entry_flags = 0U;

	if (!multiply_size(header->function_count,
			   POLICY_WIRE_FUNCTION_BYTES,
			   &function_bytes) ||
	    !add_size(header->functions_offset, function_bytes,
		      &expected_end) ||
	    expected_end != header->total_size) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
			    cursor->offset);
		return cursor->status;
	}
	for (uint32_t index = 0U;
	     index < header->function_count &&
	     cursor->status == PQCP_FLEET_POLICY_OK; ++index) {
		struct pqcp_fleet_policy_function function;
		const size_t start = cursor->offset;

		function.first_instruction = cursor_u32(cursor);
		function.instruction_count = cursor_u32(cursor);
		function.parameter_count = cursor_u16(cursor);
		function.local_count = cursor_u16(cursor);
		function.result_count = cursor_u8(cursor);
		function.flags = cursor_u8(cursor);
		function.reserved = cursor_u16(cursor);
		if (function.instruction_count == 0U ||
		    function.first_instruction != next_instruction ||
		    function.instruction_count >
			    header->instruction_count -
				    function.first_instruction ||
		    function.parameter_count > function.local_count ||
		    function.result_count > 1U ||
		    (function.flags &
		     ~PQCP_FLEET_POLICY_FUNCTION_ENTRY) != 0U ||
		    function.reserved != 0U) {
			cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_BAD_MODULE,
				    start);
		}
		if ((function.flags &
		     PQCP_FLEET_POLICY_FUNCTION_ENTRY) != 0U) {
			entry_flags++;
			if (index != header->entry_function ||
			    function.parameter_count != 0U ||
			    function.result_count != 0U) {
				cursor_fail(
					cursor,
					PQCP_FLEET_POLICY_ERR_BAD_MODULE,
					start);
			}
		}
		next_instruction += function.instruction_count;
		if (functions != NULL &&
		    cursor->status == PQCP_FLEET_POLICY_OK) {
			functions[index] = function;
		}
	}
	if (cursor->status == PQCP_FLEET_POLICY_OK &&
	    (next_instruction != header->instruction_count ||
	     entry_flags != 1U)) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_BAD_MODULE,
			    cursor->offset);
	}
	if (cursor->status == PQCP_FLEET_POLICY_OK &&
	    cursor->offset != cursor->length) {
		cursor_fail(cursor, PQCP_FLEET_POLICY_ERR_CODEC,
			    cursor->offset);
	}
	return cursor->status;
}

static int decode_pass(
	const uint8_t *input,
	size_t input_length,
	struct decoded_header *header,
	struct pqcp_fleet_policy_instruction *instructions,
	struct pqcp_fleet_policy_value *constants,
	struct pqcp_fleet_policy_function *functions,
	size_t *fault_offset)
{
	struct decode_cursor cursor = {
		.input = input,
		.length = input_length,
		.offset = 0U,
		.fault_offset = 0U,
		.status = PQCP_FLEET_POLICY_OK,
	};

	memset(header, 0, sizeof(*header));
	(void)decode_header(&cursor, header);
	if (cursor.status == PQCP_FLEET_POLICY_OK) {
		(void)decode_instructions(&cursor, header, instructions);
	}
	if (cursor.status == PQCP_FLEET_POLICY_OK) {
		(void)decode_constants(&cursor, header, constants);
	}
	if (cursor.status == PQCP_FLEET_POLICY_OK) {
		(void)decode_functions(&cursor, header, functions);
	}
	if (fault_offset != NULL) {
		*fault_offset = cursor.fault_offset;
	}
	return cursor.status;
}

static int digest_wire(
	const uint8_t *input,
	size_t input_length,
	uint8_t digest[PQCP_FLEET_POLICY_DIGEST_BYTES])
{
	struct sha256_state state;
	static const uint8_t zeros[PQCP_FLEET_POLICY_DIGEST_BYTES] = {0};

	if (input_length < POLICY_WIRE_HEADER_BYTES) {
		return PQCP_FLEET_POLICY_ERR_CODEC;
	}
	sha256_init(&state);
	sha256_update(&state, input, POLICY_WIRE_DIGEST_OFFSET);
	sha256_update(&state, zeros, sizeof(zeros));
	sha256_update(
		&state,
		input + POLICY_WIRE_DIGEST_OFFSET +
			PQCP_FLEET_POLICY_DIGEST_BYTES,
		input_length - POLICY_WIRE_DIGEST_OFFSET -
			PQCP_FLEET_POLICY_DIGEST_BYTES);
	sha256_final(&state, digest);
	return PQCP_FLEET_POLICY_OK;
}

int pqcp_fleet_policy_module_encoded_size(
	const struct pqcp_fleet_policy_module *module,
	size_t *encoded_size)
{
	if (encoded_size == NULL) {
		return PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT;
	}
	*encoded_size = 0U;
	return module_size_and_offsets(
		module, encoded_size, NULL, NULL, NULL);
}

int pqcp_fleet_policy_module_encode(
	const struct pqcp_fleet_policy_module *module,
	uint8_t *output,
	size_t output_capacity,
	struct pqcp_fleet_policy_codec_result *result)
{
	struct buffer_sink buffer;
	struct codec_sink sink;
	uint8_t digest[PQCP_FLEET_POLICY_DIGEST_BYTES];
	size_t encoded_size = 0U;
	int status;

	result_reset(result);
	if (module == NULL || output == NULL) {
		return result_fail(
			result, PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT,
			0U, 0U, 0U);
	}
	status = module_size_and_offsets(
		module, &encoded_size, NULL, NULL, NULL);
	if (status != PQCP_FLEET_POLICY_OK) {
		return result_fail(result, status, 0U, 0U, 0U);
	}
	if (output_capacity < encoded_size) {
		return result_fail(
			result, PQCP_FLEET_POLICY_ERR_CAPACITY,
			0U, 0U, encoded_size);
	}
	status = digest_module(module, digest);
	if (status != PQCP_FLEET_POLICY_OK) {
		return result_fail(result, status, 0U, 0U, 0U);
	}
	if ((module->flags &
	     PQCP_FLEET_POLICY_MODULE_REQUIRE_DIGEST) != 0U &&
	    !digest_equal(module->digest, digest)) {
		memset(digest, 0, sizeof(digest));
		return result_fail(
			result, PQCP_FLEET_POLICY_ERR_DIGEST,
			0U, 0U, POLICY_WIRE_DIGEST_OFFSET);
	}
	buffer.output = output;
	buffer.capacity = output_capacity;
	sink.context = &buffer;
	sink.write = buffer_write;
	sink.offset = 0U;
	sink.status = PQCP_FLEET_POLICY_OK;
	status = emit_module(module, &sink, digest);
	memset(digest, 0, sizeof(digest));
	if (status != PQCP_FLEET_POLICY_OK) {
		return result_fail(
			result, status, 0U, sink.offset, sink.offset);
	}
	if (result != NULL) {
		result->status = PQCP_FLEET_POLICY_OK;
		result->bytes_produced = sink.offset;
	}
	return PQCP_FLEET_POLICY_OK;
}

int pqcp_fleet_policy_module_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_fleet_policy_codec_storage *storage,
	struct pqcp_fleet_policy_module *module,
	struct pqcp_fleet_policy_codec_result *result)
{
	struct decoded_header header;
	struct pqcp_fleet_policy_module decoded;
	uint8_t digest[PQCP_FLEET_POLICY_DIGEST_BYTES];
	size_t fault_offset = 0U;
	int status;

	result_reset(result);
	if (input == NULL || storage == NULL || module == NULL) {
		return result_fail(
			result, PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT,
			0U, 0U, 0U);
	}
	status = decode_pass(
		input, input_length, &header,
		NULL, NULL, NULL, &fault_offset);
	if (status != PQCP_FLEET_POLICY_OK) {
		return result_fail(
			result, status, fault_offset, 0U, fault_offset);
	}
	if (header.instruction_count > storage->instruction_capacity ||
	    header.constant_count > storage->constant_capacity ||
	    header.function_count > storage->function_capacity ||
	    (header.instruction_count != 0U &&
	     storage->instructions == NULL) ||
	    (header.constant_count != 0U &&
	     storage->constants == NULL) ||
	    (header.function_count != 0U &&
	     storage->functions == NULL)) {
		return result_fail(
			result, PQCP_FLEET_POLICY_ERR_CAPACITY,
			input_length, 0U, 0U);
	}
	status = digest_wire(input, input_length, digest);
	if (status != PQCP_FLEET_POLICY_OK ||
	    !digest_equal(header.digest, digest)) {
		memset(digest, 0, sizeof(digest));
		return result_fail(
			result, PQCP_FLEET_POLICY_ERR_DIGEST,
			input_length, 0U, POLICY_WIRE_DIGEST_OFFSET);
	}
	status = decode_pass(
		input, input_length, &header,
		storage->instructions, storage->constants,
		storage->functions, &fault_offset);
	if (status != PQCP_FLEET_POLICY_OK) {
		memset(digest, 0, sizeof(digest));
		return result_fail(
			result, status, fault_offset, 0U, fault_offset);
	}
	memset(&decoded, 0, sizeof(decoded));
	decoded.abi_version = header.abi_version;
	decoded.bytecode_version = header.bytecode_version;
	decoded.flags = header.flags;
	decoded.entry_function = header.entry_function;
	decoded.instructions = storage->instructions;
	decoded.instruction_count = header.instruction_count;
	decoded.constants = storage->constants;
	decoded.constant_count = header.constant_count;
	decoded.functions = storage->functions;
	decoded.function_count = header.function_count;
	decoded.bounds = header.bounds;
	memcpy(decoded.digest, digest, sizeof(decoded.digest));
	*module = decoded;
	memset(digest, 0, sizeof(digest));
	if (result != NULL) {
		result->status = PQCP_FLEET_POLICY_OK;
		result->bytes_consumed = input_length;
	}
	return PQCP_FLEET_POLICY_OK;
}

int pqcp_fleet_policy_module_digest(
	const struct pqcp_fleet_policy_module *module,
	uint8_t digest[PQCP_FLEET_POLICY_DIGEST_BYTES])
{
	if (module == NULL || digest == NULL) {
		return PQCP_FLEET_POLICY_ERR_INVALID_ARGUMENT;
	}
	return digest_module(module, digest);
}
