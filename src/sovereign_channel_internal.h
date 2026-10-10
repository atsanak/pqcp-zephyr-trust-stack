/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#ifndef PQCP_SOVEREIGN_CHANNEL_INTERNAL_H_
#define PQCP_SOVEREIGN_CHANNEL_INTERNAL_H_

#include <pqcp_zephyr/sovereign_channel.h>

struct pqcp_sovereign_channel_wire_writer {
	uint8_t *output;
	size_t capacity;
	size_t offset;
	uint16_t field_count;
	uint16_t last_field;
};

struct pqcp_sovereign_channel_wire_reader {
	const uint8_t *input;
	size_t length;
	size_t offset;
	uint16_t remaining_fields;
	uint16_t last_field;
};

struct pqcp_sovereign_channel_wire_field {
	uint16_t id;
	uint16_t flags;
	const uint8_t *value;
	uint32_t length;
};

bool pqcp_sovereign_channel_internal_all_zero(
	const uint8_t *value,
	size_t length);
bool pqcp_sovereign_channel_internal_equal(
	const uint8_t *left,
	const uint8_t *right,
	size_t length);
bool pqcp_sovereign_channel_internal_frame_type_valid(
	enum pqcp_sovereign_channel_frame_type type);
uint32_t pqcp_sovereign_channel_internal_allowed_flags(
	enum pqcp_sovereign_channel_frame_type type);
int pqcp_sovereign_channel_internal_copy_text(
	char *destination,
	size_t capacity,
	const uint8_t *source,
	size_t source_length);
int pqcp_sovereign_channel_internal_hash_body(
	const uint8_t *input,
	size_t input_length,
	const uint8_t *aux_input,
	size_t aux_input_length,
	const uint8_t *context,
	size_t context_length,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES]);
int pqcp_sovereign_channel_internal_seed_digest(
	const uint8_t transaction_id[
		PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES],
	const uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	uint32_t input_length,
	uint32_t aux_length,
	uint32_t context_length,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES]);
int pqcp_sovereign_channel_internal_roll_digest(
	const uint8_t previous[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES],
	uint64_t offset,
	const uint8_t *data,
	size_t data_length,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES]);
int pqcp_sovereign_channel_internal_encode_handle(
	const struct pqcp_runtime_key_handle *handle,
	uint8_t output[PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES]);
int pqcp_sovereign_channel_internal_decode_handle(
	const uint8_t input[PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES],
	struct pqcp_runtime_key_handle *handle);
int pqcp_sovereign_channel_internal_encode_metadata(
	const struct pqcp_runtime_key_metadata *metadata,
	uint8_t output[PQCP_SOVEREIGN_CHANNEL_METADATA_BYTES]);
int pqcp_sovereign_channel_internal_decode_metadata(
	const uint8_t input[PQCP_SOVEREIGN_CHANNEL_METADATA_BYTES],
	struct pqcp_runtime_key_metadata *metadata);
struct pqcp_channel_stream *pqcp_sovereign_channel_internal_stream(
	struct pqcp_channel_multiplexer *multiplexer,
	uint32_t stream_id);
int pqcp_sovereign_channel_internal_send_frame(
	struct pqcp_sovereign_channel_flow_adapter *flow,
	uint32_t stream_id,
	const struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms);
int pqcp_sovereign_channel_internal_receive_frame(
	struct pqcp_sovereign_channel_flow_adapter *flow,
	struct pqcp_channel_stream_header *stream_header,
	struct pqcp_sovereign_channel_frame *frame,
	uint64_t now_ms);
uint32_t pqcp_sovereign_channel_internal_next_generation(
	uint32_t *generation);
int pqcp_sovereign_channel_internal_receipt_digest(
	const uint8_t *receipt,
	size_t receipt_length,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES]);
int pqcp_sovereign_channel_internal_broker_request_digest(
	const struct pqcp_sovereign_channel_begin *begin,
	const struct pqcp_sovereign_channel_request_assembler *assembler,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES]);

#endif /* PQCP_SOVEREIGN_CHANNEL_INTERNAL_H_ */
