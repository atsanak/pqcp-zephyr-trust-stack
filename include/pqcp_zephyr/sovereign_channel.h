/*
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free broker operations over authenticated protected channels.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_SOVEREIGN_CHANNEL_H_
#define PQCP_ZEPHYR_SOVEREIGN_CHANNEL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <pqcp_zephyr/crypto_broker.h>
#include <pqcp_zephyr/protected_channel_operations.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_SOVEREIGN_CHANNEL_SCHEMA_VERSION 1U
#define PQCP_SOVEREIGN_CHANNEL_MAGIC 0x534f5643U
#define PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES 64U
#define PQCP_SOVEREIGN_CHANNEL_FIELD_HEADER_BYTES 8U
#define PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES 4096U
#define PQCP_SOVEREIGN_CHANNEL_MAX_FIELD_BYTES \
	(PQCP_SOVEREIGN_CHANNEL_MAX_FRAME_BYTES - \
	 PQCP_SOVEREIGN_CHANNEL_WIRE_HEADER_BYTES - \
	 PQCP_SOVEREIGN_CHANNEL_FIELD_HEADER_BYTES)
#define PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES 16U
#define PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES 32U
#define PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES PQCP_RUNTIME_DIGEST_BYTES
#define PQCP_SOVEREIGN_CHANNEL_DETAIL_MAX_BYTES 128U
#define PQCP_SOVEREIGN_CHANNEL_RECEIPT_MAX_BYTES \
	(512U + PQCP_MLDSA_SIG_SIZE_MAX)
#define PQCP_SOVEREIGN_CHANNEL_MAX_BODY_BYTES \
	(PQCP_RUNTIME_MAX_INPUT_BYTES + \
	 PQCP_RUNTIME_MAX_INPUT_BYTES + \
	 PQCP_RUNTIME_MAX_CONTEXT_BYTES)
#define PQCP_SOVEREIGN_CHANNEL_HANDLE_BYTES 20U
#define PQCP_SOVEREIGN_CHANNEL_METADATA_BYTES 148U

#define PQCP_SOVEREIGN_CHANNEL_FIELD_MANDATORY (1U << 0)

enum pqcp_sovereign_channel_frame_type {
	PQCP_SOVEREIGN_CHANNEL_FRAME_NONE = 0,
	PQCP_SOVEREIGN_CHANNEL_FRAME_BEGIN = 1,
	PQCP_SOVEREIGN_CHANNEL_FRAME_CHUNK = 2,
	PQCP_SOVEREIGN_CHANNEL_FRAME_COMMIT = 3,
	PQCP_SOVEREIGN_CHANNEL_FRAME_CANCEL = 4,
	PQCP_SOVEREIGN_CHANNEL_FRAME_RESULT = 5,
	PQCP_SOVEREIGN_CHANNEL_FRAME_ERROR = 6,
	PQCP_SOVEREIGN_CHANNEL_FRAME_RECEIPT = 7,
	PQCP_SOVEREIGN_CHANNEL_FRAME_WINDOW = 8,
};

enum pqcp_sovereign_channel_frame_flag {
	PQCP_SOVEREIGN_CHANNEL_FLAG_FIRST = (1U << 0),
	PQCP_SOVEREIGN_CHANNEL_FLAG_FINAL = (1U << 1),
	PQCP_SOVEREIGN_CHANNEL_FLAG_ACK = (1U << 2),
	PQCP_SOVEREIGN_CHANNEL_FLAG_RESUME = (1U << 3),
	PQCP_SOVEREIGN_CHANNEL_FLAG_RETRYABLE = (1U << 4),
	PQCP_SOVEREIGN_CHANNEL_FLAG_REPLAYED = (1U << 5),
	PQCP_SOVEREIGN_CHANNEL_FLAG_CANCELLED = (1U << 6),
	PQCP_SOVEREIGN_CHANNEL_FLAG_ACCEPTED = (1U << 7),
};

enum pqcp_sovereign_channel_field_id {
	PQCP_SOVEREIGN_CHANNEL_FIELD_PRINCIPAL_ID = 1,
	PQCP_SOVEREIGN_CHANNEL_FIELD_TENANT_ID = 2,
	PQCP_SOVEREIGN_CHANNEL_FIELD_CAPABILITY = 3,
	PQCP_SOVEREIGN_CHANNEL_FIELD_OPERATION = 4,
	PQCP_SOVEREIGN_CHANNEL_FIELD_SUBMITTED_AT = 5,
	PQCP_SOVEREIGN_CHANNEL_FIELD_DEADLINE = 6,
	PQCP_SOVEREIGN_CHANNEL_FIELD_REQUEST_FLAGS = 7,
	PQCP_SOVEREIGN_CHANNEL_FIELD_LEVEL = 8,
	PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_FAMILY = 9,
	PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_LEVEL = 10,
	PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_USAGE = 11,
	PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_EXPIRES_AT = 12,
	PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_OPTIONS = 13,
	PQCP_SOVEREIGN_CHANNEL_FIELD_KEY_LABEL = 14,
	PQCP_SOVEREIGN_CHANNEL_FIELD_PRIMARY_KEY = 15,
	PQCP_SOVEREIGN_CHANNEL_FIELD_SECONDARY_KEY = 16,
	PQCP_SOVEREIGN_CHANNEL_FIELD_INPUT_LENGTH = 17,
	PQCP_SOVEREIGN_CHANNEL_FIELD_AUX_LENGTH = 18,
	PQCP_SOVEREIGN_CHANNEL_FIELD_CONTEXT_LENGTH = 19,
	PQCP_SOVEREIGN_CHANNEL_FIELD_CONTENT_DIGEST = 20,
	PQCP_SOVEREIGN_CHANNEL_FIELD_RESUME_TOKEN = 21,
	PQCP_SOVEREIGN_CHANNEL_FIELD_OFFSET = 22,
	PQCP_SOVEREIGN_CHANNEL_FIELD_DATA = 23,
	PQCP_SOVEREIGN_CHANNEL_FIELD_ROLLING_DIGEST = 24,
	PQCP_SOVEREIGN_CHANNEL_FIELD_TOTAL_LENGTH = 25,
	PQCP_SOVEREIGN_CHANNEL_FIELD_ERROR_CODE = 26,
	PQCP_SOVEREIGN_CHANNEL_FIELD_DETAIL = 27,
	PQCP_SOVEREIGN_CHANNEL_FIELD_RESULT_CODE = 28,
	PQCP_SOVEREIGN_CHANNEL_FIELD_RESULT_FLAGS = 29,
	PQCP_SOVEREIGN_CHANNEL_FIELD_METADATA = 30,
	PQCP_SOVEREIGN_CHANNEL_FIELD_ACK_OFFSET = 31,
	PQCP_SOVEREIGN_CHANNEL_FIELD_ERROR_STAGE = 32,
	PQCP_SOVEREIGN_CHANNEL_FIELD_RETRY_AFTER = 33,
	PQCP_SOVEREIGN_CHANNEL_FIELD_CONNECTION_CREDIT = 34,
	PQCP_SOVEREIGN_CHANNEL_FIELD_STREAM_CREDIT = 35,
	PQCP_SOVEREIGN_CHANNEL_FIELD_WINDOW_KIND = 36,
	PQCP_SOVEREIGN_CHANNEL_FIELD_RECEIPT_SEQUENCE = 37,
	PQCP_SOVEREIGN_CHANNEL_FIELD_RECEIPT_DIGEST = 38,
	PQCP_SOVEREIGN_CHANNEL_FIELD_SERVER_TIME = 39,
	PQCP_SOVEREIGN_CHANNEL_FIELD_EXPIRY = 40,
	PQCP_SOVEREIGN_CHANNEL_FIELD_COUNT,
};

enum pqcp_sovereign_channel_window_kind {
	PQCP_SOVEREIGN_CHANNEL_WINDOW_CREDIT = 1,
	PQCP_SOVEREIGN_CHANNEL_WINDOW_BEGIN_ACCEPTED = 2,
	PQCP_SOVEREIGN_CHANNEL_WINDOW_REQUEST_ACK = 3,
	PQCP_SOVEREIGN_CHANNEL_WINDOW_RESULT_ACK = 4,
	PQCP_SOVEREIGN_CHANNEL_WINDOW_RECEIPT_ACK = 5,
	PQCP_SOVEREIGN_CHANNEL_WINDOW_RESUME_ACCEPTED = 6,
	PQCP_SOVEREIGN_CHANNEL_WINDOW_COMPLETE = 7,
};

enum pqcp_sovereign_channel_error_stage {
	PQCP_SOVEREIGN_CHANNEL_STAGE_NONE = 0,
	PQCP_SOVEREIGN_CHANNEL_STAGE_DECODE,
	PQCP_SOVEREIGN_CHANNEL_STAGE_IDENTITY,
	PQCP_SOVEREIGN_CHANNEL_STAGE_BEGIN,
	PQCP_SOVEREIGN_CHANNEL_STAGE_ASSEMBLY,
	PQCP_SOVEREIGN_CHANNEL_STAGE_COMMIT,
	PQCP_SOVEREIGN_CHANNEL_STAGE_BROKER,
	PQCP_SOVEREIGN_CHANNEL_STAGE_RESULT,
	PQCP_SOVEREIGN_CHANNEL_STAGE_RECEIPT,
	PQCP_SOVEREIGN_CHANNEL_STAGE_FLOW,
	PQCP_SOVEREIGN_CHANNEL_STAGE_RESUME,
};

enum pqcp_sovereign_channel_server_state {
	PQCP_SOVEREIGN_CHANNEL_SERVER_EMPTY = 0,
	PQCP_SOVEREIGN_CHANNEL_SERVER_RECEIVING,
	PQCP_SOVEREIGN_CHANNEL_SERVER_READY,
	PQCP_SOVEREIGN_CHANNEL_SERVER_EXECUTING,
	PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RESULT,
	PQCP_SOVEREIGN_CHANNEL_SERVER_SENDING_RECEIPT,
	PQCP_SOVEREIGN_CHANNEL_SERVER_WAITING_ACK,
	PQCP_SOVEREIGN_CHANNEL_SERVER_DISCONNECTED,
	PQCP_SOVEREIGN_CHANNEL_SERVER_COMPLETED,
	PQCP_SOVEREIGN_CHANNEL_SERVER_CANCELLED,
	PQCP_SOVEREIGN_CHANNEL_SERVER_FAILED,
};

enum pqcp_sovereign_channel_client_state {
	PQCP_SOVEREIGN_CHANNEL_CLIENT_EMPTY = 0,
	PQCP_SOVEREIGN_CHANNEL_CLIENT_BEGIN_SENT,
	PQCP_SOVEREIGN_CHANNEL_CLIENT_SENDING,
	PQCP_SOVEREIGN_CHANNEL_CLIENT_COMMIT_SENT,
	PQCP_SOVEREIGN_CHANNEL_CLIENT_WAITING_RESULT,
	PQCP_SOVEREIGN_CHANNEL_CLIENT_RECEIVING_RESULT,
	PQCP_SOVEREIGN_CHANNEL_CLIENT_RECEIVING_RECEIPT,
	PQCP_SOVEREIGN_CHANNEL_CLIENT_DISCONNECTED,
	PQCP_SOVEREIGN_CHANNEL_CLIENT_COMPLETED,
	PQCP_SOVEREIGN_CHANNEL_CLIENT_CANCELLED,
	PQCP_SOVEREIGN_CHANNEL_CLIENT_FAILED,
};

enum pqcp_sovereign_channel_key_option {
	PQCP_SOVEREIGN_CHANNEL_KEY_PERSISTENT = (1U << 0),
	PQCP_SOVEREIGN_CHANNEL_KEY_EXPORTABLE_PUBLIC = (1U << 1),
};

struct pqcp_sovereign_channel_begin {
	char principal_id[PQCP_CRYPTO_BROKER_ID_MAX_CHARS];
	char tenant_id[PQCP_CRYPTO_BROKER_TENANT_MAX_CHARS];
	uint8_t capability[PQCP_CRYPTO_BROKER_TOKEN_BYTES];
	enum pqcp_crypto_broker_operation operation;
	uint64_t submitted_at_ms;
	uint64_t deadline_ms;
	uint32_t request_flags;
	uint32_t level;
	struct pqcp_crypto_broker_key_spec key_spec;
	struct pqcp_runtime_key_handle primary_key;
	struct pqcp_runtime_key_handle secondary_key;
	uint32_t input_length;
	uint32_t aux_input_length;
	uint32_t context_length;
	uint8_t content_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t resume_token[PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES];
	bool has_resume_token;
};

struct pqcp_sovereign_channel_chunk {
	uint64_t offset;
	const uint8_t *data;
	size_t data_length;
	uint8_t rolling_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
};

struct pqcp_sovereign_channel_commit {
	uint64_t total_length;
	uint8_t rolling_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t content_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
};

struct pqcp_sovereign_channel_cancel {
	int error_code;
	uint8_t detail[PQCP_SOVEREIGN_CHANNEL_DETAIL_MAX_BYTES];
	size_t detail_length;
};

struct pqcp_sovereign_channel_result {
	int result_code;
	uint32_t result_flags;
	struct pqcp_runtime_key_handle primary_key;
	struct pqcp_runtime_key_handle secondary_key;
	struct pqcp_runtime_key_metadata metadata;
	uint64_t total_length;
	uint64_t offset;
	const uint8_t *data;
	size_t data_length;
	uint8_t content_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint64_t ack_offset;
};

struct pqcp_sovereign_channel_error {
	int error_code;
	enum pqcp_sovereign_channel_error_stage stage;
	uint64_t retry_after_ms;
	uint8_t detail[PQCP_SOVEREIGN_CHANNEL_DETAIL_MAX_BYTES];
	size_t detail_length;
};

struct pqcp_sovereign_channel_receipt_frame {
	uint64_t total_length;
	uint64_t offset;
	const uint8_t *data;
	size_t data_length;
	uint8_t content_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint64_t receipt_sequence;
	uint8_t receipt_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint64_t ack_offset;
};

struct pqcp_sovereign_channel_window {
	enum pqcp_sovereign_channel_window_kind kind;
	uint32_t connection_credit;
	uint32_t stream_credit;
	uint64_t ack_offset;
	uint8_t resume_token[PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES];
	uint8_t rolling_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint64_t server_time_ms;
	uint64_t expires_at_ms;
	bool has_resume_token;
	bool has_rolling_digest;
};

struct pqcp_sovereign_channel_frame {
	uint32_t schema_version;
	enum pqcp_sovereign_channel_frame_type type;
	uint32_t flags;
	uint64_t sequence;
	uint8_t transaction_id[PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES];
	uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES];
	union {
		struct pqcp_sovereign_channel_begin begin;
		struct pqcp_sovereign_channel_chunk chunk;
		struct pqcp_sovereign_channel_commit commit;
		struct pqcp_sovereign_channel_cancel cancel;
		struct pqcp_sovereign_channel_result result;
		struct pqcp_sovereign_channel_error error;
		struct pqcp_sovereign_channel_receipt_frame receipt;
		struct pqcp_sovereign_channel_window window;
	} body;
};

struct pqcp_sovereign_channel_request_assembler {
	uint8_t *input;
	size_t input_capacity;
	uint8_t *aux_input;
	size_t aux_input_capacity;
	uint8_t *context;
	size_t context_capacity;
	uint32_t expected_input_length;
	uint32_t expected_aux_length;
	uint32_t expected_context_length;
	uint64_t expected_total_length;
	uint64_t received_length;
	uint8_t transaction_id[PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES];
	uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES];
	uint8_t expected_content_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t rolling_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	bool initialized;
	bool committed;
};

struct pqcp_sovereign_channel_blob_assembler {
	uint8_t *output;
	size_t output_capacity;
	uint64_t expected_length;
	uint64_t received_length;
	uint8_t expected_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	bool initialized;
	bool completed;
};

struct pqcp_sovereign_channel_flow_adapter {
	struct pqcp_channel_multiplexer *multiplexer;
	struct pqcp_channel_flow_controller *controller;
	uint32_t maximum_frame_bytes;
	uint64_t frames_sent;
	uint64_t frames_received;
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t updates_sent;
	uint64_t updates_received;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_channel_resume_claim {
	uint32_t schema_version;
	uint8_t transaction_id[PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES];
	uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES];
	uint8_t identity_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t capability_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t request_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint64_t received_offset;
	uint64_t result_ack_offset;
	uint64_t receipt_ack_offset;
	uint64_t issued_at_ms;
	uint64_t expires_at_ms;
	uint32_t generation;
};

struct pqcp_sovereign_channel_server_buffer {
	uint8_t *input;
	size_t input_capacity;
	uint8_t *aux_input;
	size_t aux_input_capacity;
	uint8_t *context;
	size_t context_capacity;
	uint8_t *output;
	size_t output_capacity;
	uint8_t *receipt;
	size_t receipt_capacity;
};

struct pqcp_sovereign_channel_server_slot {
	uint32_t schema_version;
	uint32_t generation;
	enum pqcp_sovereign_channel_server_state state;
	uint32_t stream_id;
	uint64_t next_receive_sequence;
	uint64_t next_send_sequence;
	uint64_t created_at_ms;
	uint64_t last_activity_ms;
	uint64_t expires_at_ms;
	uint64_t disconnected_at_ms;
	uint8_t transaction_id[PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES];
	uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES];
	uint8_t identity_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t request_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t capability_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t resume_token[PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES];
	char principal_id[PQCP_CRYPTO_BROKER_ID_MAX_CHARS];
	char tenant_id[PQCP_CRYPTO_BROKER_TENANT_MAX_CHARS];
	struct pqcp_sovereign_channel_begin begin;
	struct pqcp_sovereign_channel_request_assembler assembler;
	struct pqcp_sovereign_channel_server_buffer buffers;
	struct pqcp_crypto_broker_response response;
	size_t result_send_offset;
	size_t result_ack_offset;
	size_t receipt_length;
	size_t receipt_send_offset;
	size_t receipt_ack_offset;
	uint8_t result_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t receipt_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	int terminal_result;
	bool occupied;
	bool broker_executed;
	bool result_announced;
	bool receipt_announced;
};

struct pqcp_sovereign_channel_server_storage {
	struct pqcp_sovereign_channel_server_slot *slots;
	const struct pqcp_sovereign_channel_server_buffer *buffers;
	size_t capacity;
};

typedef int (*pqcp_sovereign_channel_identity_resolver)(
	void *context,
	const uint8_t identity_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES],
	char principal_id[PQCP_CRYPTO_BROKER_ID_MAX_CHARS],
	char tenant_id[PQCP_CRYPTO_BROKER_TENANT_MAX_CHARS]);

struct pqcp_sovereign_channel_server_config {
	struct pqcp_crypto_broker *broker;
	struct pqcp_channel_multiplexer *multiplexer;
	struct pqcp_channel_flow_controller *flow_controller;
	pqcp_sovereign_channel_identity_resolver resolve_identity;
	void *identity_context;
	const uint8_t *resume_secret;
	size_t resume_secret_length;
	uint64_t transaction_lifetime_ms;
	uint64_t disconnected_retention_ms;
	uint32_t stream_priority;
	bool require_mutual_authentication;
};

struct pqcp_sovereign_channel_server {
	struct pqcp_sovereign_channel_server_config config;
	struct pqcp_sovereign_channel_server_storage storage;
	struct pqcp_sovereign_channel_flow_adapter flow;
	uint32_t next_generation;
	uint64_t accepted_transactions;
	uint64_t resumed_transactions;
	uint64_t completed_transactions;
	uint64_t cancelled_transactions;
	uint64_t failed_transactions;
	uint64_t rejected_frames;
	struct k_mutex lock;
	bool initialized;
};

struct pqcp_sovereign_channel_client_transaction {
	uint32_t schema_version;
	uint32_t generation;
	enum pqcp_sovereign_channel_client_state state;
	uint32_t stream_id;
	uint64_t next_send_sequence;
	uint64_t next_receive_sequence;
	uint64_t created_at_ms;
	uint64_t last_activity_ms;
	uint64_t expires_at_ms;
	uint8_t transaction_id[PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES];
	uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES];
	uint8_t resume_token[PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES];
	struct pqcp_sovereign_channel_begin begin;
	const uint8_t *input;
	size_t input_length;
	const uint8_t *aux_input;
	size_t aux_input_length;
	const uint8_t *context;
	size_t context_length;
	uint64_t send_offset;
	uint8_t rolling_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES];
	uint8_t *result;
	size_t result_capacity;
	struct pqcp_sovereign_channel_blob_assembler result_assembler;
	uint8_t *receipt;
	size_t receipt_capacity;
	struct pqcp_sovereign_channel_blob_assembler receipt_assembler;
	struct pqcp_crypto_broker_response response;
	uint64_t result_ack_offset;
	uint64_t receipt_ack_offset;
	int terminal_result;
	bool has_resume_token;
	bool result_header_received;
	bool receipt_header_received;
	bool occupied;
};

struct pqcp_sovereign_channel_client_storage {
	struct pqcp_sovereign_channel_client_transaction *transactions;
	size_t capacity;
};

struct pqcp_sovereign_channel_client_config {
	struct pqcp_channel_multiplexer *multiplexer;
	struct pqcp_channel_flow_controller *flow_controller;
	uint64_t transaction_lifetime_ms;
	uint32_t stream_priority;
};

struct pqcp_sovereign_channel_client {
	struct pqcp_sovereign_channel_client_config config;
	struct pqcp_sovereign_channel_client_storage storage;
	struct pqcp_sovereign_channel_flow_adapter flow;
	uint32_t next_generation;
	uint64_t started_transactions;
	uint64_t resumed_transactions;
	uint64_t completed_transactions;
	uint64_t failed_transactions;
	uint64_t rejected_frames;
	struct k_mutex lock;
	bool initialized;
};

const char *pqcp_sovereign_channel_frame_type_str(
	enum pqcp_sovereign_channel_frame_type type);
const char *pqcp_sovereign_channel_server_state_str(
	enum pqcp_sovereign_channel_server_state state);
const char *pqcp_sovereign_channel_client_state_str(
	enum pqcp_sovereign_channel_client_state state);

int pqcp_sovereign_channel_frame_encode(
	const struct pqcp_sovereign_channel_frame *frame,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_sovereign_channel_frame_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_sovereign_channel_frame *frame);

int pqcp_sovereign_channel_request_assembler_init(
	struct pqcp_sovereign_channel_request_assembler *assembler,
	const struct pqcp_sovereign_channel_begin *begin,
	const uint8_t transaction_id[
		PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES],
	const uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	uint8_t *input,
	size_t input_capacity,
	uint8_t *aux_input,
	size_t aux_input_capacity,
	uint8_t *context,
	size_t context_capacity);
int pqcp_sovereign_channel_request_assembler_append(
	struct pqcp_sovereign_channel_request_assembler *assembler,
	const struct pqcp_sovereign_channel_chunk *chunk);
int pqcp_sovereign_channel_request_assembler_commit(
	struct pqcp_sovereign_channel_request_assembler *assembler,
	const struct pqcp_sovereign_channel_commit *commit);
int pqcp_sovereign_channel_request_assembler_reset(
	struct pqcp_sovereign_channel_request_assembler *assembler);
int pqcp_sovereign_channel_request_assembler_audit(
	const struct pqcp_sovereign_channel_request_assembler *assembler);

int pqcp_sovereign_channel_blob_assembler_init(
	struct pqcp_sovereign_channel_blob_assembler *assembler,
	uint8_t *output,
	size_t output_capacity,
	uint64_t expected_length,
	const uint8_t expected_digest[
		PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES]);
int pqcp_sovereign_channel_blob_assembler_append(
	struct pqcp_sovereign_channel_blob_assembler *assembler,
	uint64_t offset,
	const uint8_t *data,
	size_t data_length,
	bool final);
int pqcp_sovereign_channel_blob_assembler_audit(
	const struct pqcp_sovereign_channel_blob_assembler *assembler);

int pqcp_sovereign_channel_flow_init(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	struct pqcp_channel_multiplexer *multiplexer,
	struct pqcp_channel_flow_controller *controller);
int pqcp_sovereign_channel_flow_send(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	uint32_t stream_id,
	const uint8_t *frame,
	size_t frame_length,
	uint32_t flags,
	uint64_t now_ms);
int pqcp_sovereign_channel_flow_receive_account(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	uint32_t stream_id,
	size_t frame_length,
	struct pqcp_sovereign_channel_window *window);
int pqcp_sovereign_channel_flow_apply_window(
	struct pqcp_sovereign_channel_flow_adapter *adapter,
	uint32_t stream_id,
	const struct pqcp_sovereign_channel_window *window);
int pqcp_sovereign_channel_flow_audit(
	struct pqcp_sovereign_channel_flow_adapter *adapter);

int pqcp_sovereign_channel_resume_token_issue(
	const uint8_t *secret,
	size_t secret_length,
	const struct pqcp_sovereign_channel_resume_claim *claim,
	uint8_t token[PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES]);
int pqcp_sovereign_channel_resume_token_verify(
	const uint8_t *secret,
	size_t secret_length,
	const struct pqcp_sovereign_channel_resume_claim *claim,
	const uint8_t token[PQCP_SOVEREIGN_CHANNEL_RESUME_TOKEN_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_channel_resume_claim_from_slot(
	const struct pqcp_sovereign_channel_server_slot *slot,
	struct pqcp_sovereign_channel_resume_claim *claim);

int pqcp_sovereign_channel_identity_digest(
	const struct pqcp_channel *channel,
	uint8_t digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES]);
int pqcp_sovereign_channel_broker_bind_identity(
	struct pqcp_crypto_broker *broker,
	const uint8_t identity_digest[PQCP_SOVEREIGN_CHANNEL_DIGEST_BYTES],
	const char *principal_id,
	const char *tenant_id);
int pqcp_sovereign_channel_broker_execute(
	struct pqcp_crypto_broker *broker,
	const struct pqcp_sovereign_channel_begin *begin,
	const struct pqcp_sovereign_channel_request_assembler *assembler,
	struct pqcp_crypto_broker_response *response);
int pqcp_sovereign_channel_broker_cancel(
	struct pqcp_crypto_broker *broker,
	const char *principal_id,
	const uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	uint64_t now_ms);
int pqcp_sovereign_channel_receipt_encode(
	const struct pqcp_crypto_broker_receipt *receipt,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_sovereign_channel_receipt_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_crypto_broker_receipt *receipt);

int pqcp_sovereign_channel_server_init(
	struct pqcp_sovereign_channel_server *server,
	const struct pqcp_sovereign_channel_server_config *config,
	const struct pqcp_sovereign_channel_server_storage *storage);
int pqcp_sovereign_channel_server_receive(
	struct pqcp_sovereign_channel_server *server,
	uint64_t now_ms);
int pqcp_sovereign_channel_server_progress(
	struct pqcp_sovereign_channel_server *server,
	uint64_t now_ms);
int pqcp_sovereign_channel_server_disconnect(
	struct pqcp_sovereign_channel_server *server,
	uint32_t stream_id,
	uint64_t now_ms);
int pqcp_sovereign_channel_server_tick(
	struct pqcp_sovereign_channel_server *server,
	uint64_t now_ms,
	uint32_t *expired_count);
int pqcp_sovereign_channel_server_audit(
	struct pqcp_sovereign_channel_server *server);

int pqcp_sovereign_channel_client_init(
	struct pqcp_sovereign_channel_client *client,
	const struct pqcp_sovereign_channel_client_config *config,
	const struct pqcp_sovereign_channel_client_storage *storage);
int pqcp_sovereign_channel_client_start(
	struct pqcp_sovereign_channel_client *client,
	const struct pqcp_sovereign_channel_begin *begin,
	const uint8_t transaction_id[
		PQCP_SOVEREIGN_CHANNEL_TRANSACTION_ID_BYTES],
	const uint8_t request_id[PQCP_CRYPTO_BROKER_REQUEST_ID_BYTES],
	const uint8_t *input,
	size_t input_length,
	const uint8_t *aux_input,
	size_t aux_input_length,
	const uint8_t *context,
	size_t context_length,
	uint8_t *result,
	size_t result_capacity,
	uint8_t *receipt,
	size_t receipt_capacity,
	uint64_t now_ms,
	struct pqcp_sovereign_channel_client_transaction **transaction);
int pqcp_sovereign_channel_client_send_next(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction *transaction,
	uint64_t now_ms);
int pqcp_sovereign_channel_client_receive(
	struct pqcp_sovereign_channel_client *client,
	uint64_t now_ms);
int pqcp_sovereign_channel_client_resume(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction *transaction,
	uint64_t now_ms);
int pqcp_sovereign_channel_client_cancel(
	struct pqcp_sovereign_channel_client *client,
	struct pqcp_sovereign_channel_client_transaction *transaction,
	int reason,
	const uint8_t *detail,
	size_t detail_length,
	uint64_t now_ms);
int pqcp_sovereign_channel_client_disconnect(
	struct pqcp_sovereign_channel_client *client,
	uint32_t stream_id,
	uint64_t now_ms);
int pqcp_sovereign_channel_client_audit(
	struct pqcp_sovereign_channel_client *client);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_SOVEREIGN_CHANNEL_H_ */
