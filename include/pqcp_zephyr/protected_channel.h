/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Exporter-bound application-layer PQC protected channel.
 *
 * This is not a TLS ciphersuite and must not be represented as standardized
 * PQC TLS. It runs after a standard TLS handshake and binds ML-KEM/ML-DSA to
 * the established TLS channel through exporter material.
 *
 * Stability: experimental.
 */

#ifndef PQCP_ZEPHYR_PROTECTED_CHANNEL_H_
#define PQCP_ZEPHYR_PROTECTED_CHANNEL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pqcp_zephyr/runtime_executor.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQCP_CHANNEL_SCHEMA_VERSION 1U
#define PQCP_CHANNEL_MAGIC 0x50514350U
#define PQCP_CHANNEL_EXPORTER_LABEL "EXPORTER-PQCP-CHANNEL-v1"
#define PQCP_CHANNEL_EXPORTER_BYTES 32U
#define PQCP_CHANNEL_NONCE_BYTES 32U
#define PQCP_CHANNEL_HASH_BYTES 32U
#define PQCP_CHANNEL_FINISHED_BYTES 32U
#define PQCP_CHANNEL_AEAD_KEY_BYTES 32U
#define PQCP_CHANNEL_AEAD_NONCE_BYTES 12U
#define PQCP_CHANNEL_AEAD_TAG_BYTES 16U
#define PQCP_CHANNEL_FRAME_HEADER_BYTES 36U
#define PQCP_CHANNEL_MAX_FRAME_BYTES 8192U
#define PQCP_CHANNEL_MAX_PAYLOAD_BYTES 4096U
#define PQCP_CHANNEL_REPLAY_WINDOW 64U

enum pqcp_channel_role {
	PQCP_CHANNEL_ROLE_CLIENT = 1,
	PQCP_CHANNEL_ROLE_SERVER = 2,
};

enum pqcp_channel_state {
	PQCP_CHANNEL_STATE_IDLE = 0,
	PQCP_CHANNEL_STATE_TLS_READY,
	PQCP_CHANNEL_STATE_HELLO_SENT,
	PQCP_CHANNEL_STATE_HELLO_RECEIVED,
	PQCP_CHANNEL_STATE_PROFILE_SELECTED,
	PQCP_CHANNEL_STATE_KEM_EXCHANGED,
	PQCP_CHANNEL_STATE_AUTHENTICATED,
	PQCP_CHANNEL_STATE_FINISHED,
	PQCP_CHANNEL_STATE_ESTABLISHED,
	PQCP_CHANNEL_STATE_CLOSING,
	PQCP_CHANNEL_STATE_CLOSED,
	PQCP_CHANNEL_STATE_FAILED,
};

enum pqcp_channel_frame_type {
	PQCP_CHANNEL_FRAME_CLIENT_HELLO = 1,
	PQCP_CHANNEL_FRAME_SERVER_HELLO = 2,
	PQCP_CHANNEL_FRAME_KEM_PUBLIC_KEY = 3,
	PQCP_CHANNEL_FRAME_KEM_CIPHERTEXT = 4,
	PQCP_CHANNEL_FRAME_SERVER_AUTH = 5,
	PQCP_CHANNEL_FRAME_CLIENT_AUTH = 6,
	PQCP_CHANNEL_FRAME_FINISHED = 7,
	PQCP_CHANNEL_FRAME_APPLICATION = 8,
	PQCP_CHANNEL_FRAME_CLOSE = 9,
	PQCP_CHANNEL_FRAME_ALERT = 10,
};

enum pqcp_channel_alert {
	PQCP_CHANNEL_ALERT_NONE = 0,
	PQCP_CHANNEL_ALERT_BAD_FRAME,
	PQCP_CHANNEL_ALERT_UNSUPPORTED_VERSION,
	PQCP_CHANNEL_ALERT_UNSUPPORTED_PROFILE,
	PQCP_CHANNEL_ALERT_REPLAY,
	PQCP_CHANNEL_ALERT_SEQUENCE,
	PQCP_CHANNEL_ALERT_AUTHENTICATION,
	PQCP_CHANNEL_ALERT_FINISHED,
	PQCP_CHANNEL_ALERT_KEY_DERIVATION,
	PQCP_CHANNEL_ALERT_INTERNAL,
	PQCP_CHANNEL_ALERT_TIMEOUT,
};

struct pqcp_channel_frame_header {
	uint32_t magic;
	uint16_t schema_version;
	uint16_t type;
	uint32_t flags;
	uint64_t session_id;
	uint64_t sequence;
	uint32_t payload_length;
	uint32_t reserved;
};

struct pqcp_channel_transport {
	void *context;
	int (*send)(void *context,
		    const uint8_t *buffer,
		    size_t length,
		    uint32_t timeout_ms);
	int (*receive)(void *context,
		       uint8_t *buffer,
		       size_t capacity,
		       size_t *received,
		       uint32_t timeout_ms);
	int (*export_keying_material)(void *context,
				      const char *label,
				      const uint8_t *export_context,
				      size_t export_context_length,
				      uint8_t *output,
				      size_t output_length);
	int (*close)(void *context);
};

struct pqcp_channel_config {
	uint32_t schema_version;
	enum pqcp_channel_role role;
	uint64_t session_id;
	uint32_t mlkem_level;
	uint32_t mldsa_level;
	uint32_t timeout_ms;
	uint32_t max_payload_bytes;
	struct pqcp_runtime_key_handle local_identity;
	uint8_t peer_identity_public[PQCP_MLDSA_PK_SIZE_MAX];
	size_t peer_identity_public_length;
	bool require_mutual_authentication;
	char profile_id[PQCP_RUNTIME_PROFILE_MAX_CHARS];
};

struct pqcp_channel_transcript {
	uint32_t schema_version;
	uint64_t bytes;
	uint64_t frames;
	uint8_t hash[PQCP_CHANNEL_HASH_BYTES];
	uint8_t chaining_state[PQCP_CHANNEL_HASH_BYTES];
	bool initialized;
	bool finalized;
};

struct pqcp_channel_replay_state {
	uint64_t highest_sequence;
	uint64_t bitmap;
	bool initialized;
};

struct pqcp_channel_keys {
	uint8_t exporter[PQCP_CHANNEL_EXPORTER_BYTES];
	uint8_t shared_secret[PQCP_MLKEM_SS_SIZE];
	uint8_t client_finished[PQCP_CHANNEL_FINISHED_BYTES];
	uint8_t server_finished[PQCP_CHANNEL_FINISHED_BYTES];
	uint8_t client_write_key[PQCP_CHANNEL_AEAD_KEY_BYTES];
	uint8_t server_write_key[PQCP_CHANNEL_AEAD_KEY_BYTES];
	uint8_t client_nonce_base[PQCP_CHANNEL_AEAD_NONCE_BYTES];
	uint8_t server_nonce_base[PQCP_CHANNEL_AEAD_NONCE_BYTES];
	bool exporter_ready;
	bool shared_secret_ready;
	bool traffic_keys_ready;
};

struct pqcp_channel {
	uint32_t schema_version;
	struct pqcp_channel_config config;
	enum pqcp_channel_state state;
	enum pqcp_channel_alert last_alert;
	struct pqcp_channel_transport transport;
	struct pqcp_runtime_executor *executor;
	struct pqcp_runtime_key_store *key_store;
	struct pqcp_channel_transcript transcript;
	struct pqcp_channel_replay_state inbound_replay;
	struct pqcp_channel_keys keys;
	struct pqcp_runtime_key_handle ephemeral_kem_key;
	uint8_t local_nonce[PQCP_CHANNEL_NONCE_BYTES];
	uint8_t peer_nonce[PQCP_CHANNEL_NONCE_BYTES];
	uint64_t send_sequence;
	uint64_t receive_sequence;
	uint64_t handshake_started_ms;
	uint64_t handshake_completed_ms;
	uint64_t frames_sent;
	uint64_t frames_received;
	uint64_t application_bytes_sent;
	uint64_t application_bytes_received;
	uint32_t failure_count;
	uint8_t tx_frame[PQCP_CHANNEL_MAX_FRAME_BYTES];
	uint8_t rx_frame[PQCP_CHANNEL_MAX_FRAME_BYTES];
	uint8_t work_buffer[PQCP_CHANNEL_MAX_FRAME_BYTES];
	bool peer_authenticated;
	bool local_authenticated;
	bool established;
};

const char *pqcp_channel_state_str(enum pqcp_channel_state state);
const char *pqcp_channel_alert_str(enum pqcp_channel_alert alert);
const char *pqcp_channel_frame_type_str(enum pqcp_channel_frame_type type);

int pqcp_channel_frame_encode(
	const struct pqcp_channel_frame_header *header,
	const uint8_t *payload,
	size_t payload_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length);
int pqcp_channel_frame_decode(
	const uint8_t *input,
	size_t input_length,
	struct pqcp_channel_frame_header *header,
	const uint8_t **payload,
	size_t *payload_length);

int pqcp_channel_transcript_init(
	struct pqcp_channel_transcript *transcript);
int pqcp_channel_transcript_update(
	struct pqcp_channel_transcript *transcript,
	const uint8_t *frame,
	size_t frame_length);
int pqcp_channel_transcript_digest(
	const struct pqcp_channel_transcript *transcript,
	uint8_t output[PQCP_CHANNEL_HASH_BYTES]);

int pqcp_channel_replay_accept(
	struct pqcp_channel_replay_state *state,
	uint64_t sequence);
int pqcp_channel_replay_reset(
	struct pqcp_channel_replay_state *state);

int pqcp_channel_init(
	struct pqcp_channel *channel,
	const struct pqcp_channel_config *config,
	const struct pqcp_channel_transport *transport,
	struct pqcp_runtime_executor *executor,
	struct pqcp_runtime_key_store *key_store);
int pqcp_channel_handshake(
	struct pqcp_channel *channel);
int pqcp_channel_send(
	struct pqcp_channel *channel,
	const uint8_t *plaintext,
	size_t plaintext_length);
int pqcp_channel_receive(
	struct pqcp_channel *channel,
	uint8_t *plaintext,
	size_t plaintext_capacity,
	size_t *plaintext_length);
int pqcp_channel_send_message(
	struct pqcp_channel *channel,
	const uint8_t *message,
	size_t message_length,
	uint32_t message_id);
int pqcp_channel_receive_message(
	struct pqcp_channel *channel,
	uint8_t *message,
	size_t message_capacity,
	size_t *message_length,
	uint32_t *message_id);
int pqcp_channel_close(
	struct pqcp_channel *channel);
int pqcp_channel_audit(
	const struct pqcp_channel *channel);
int pqcp_channel_emit(
	const struct pqcp_channel *channel);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ZEPHYR_PROTECTED_CHANNEL_H_ */
